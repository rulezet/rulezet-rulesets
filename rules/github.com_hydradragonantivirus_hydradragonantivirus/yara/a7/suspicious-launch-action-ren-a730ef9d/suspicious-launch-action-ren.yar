rule suspicious_launch_action_ren: PDF {
  meta:
    author  = "Glenn Edwards (@hiddenillusion)"
    version = "0.1"
    weight  = 2

  strings:
    $magic = "%PDF"

    $attrib0 = /\/Launch/
    $attrib1 = /\/URL /
    $attrib2 = /\/Action/
    $attrib3 = /\/F /

  condition:
    $magic at 0 and 3 of ($attrib*)
}