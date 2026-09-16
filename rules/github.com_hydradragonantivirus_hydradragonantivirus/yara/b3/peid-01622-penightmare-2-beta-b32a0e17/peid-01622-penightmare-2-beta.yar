rule PEiD_01622_PENightMare_2_Beta_ {
  meta:
    description = "[PENightMare 2 Beta]"
    ep_only     = "true"

  strings:
    $a = { 60 E9 ?? ?? ?? ?? EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C 3A }

  condition:
    $a
}