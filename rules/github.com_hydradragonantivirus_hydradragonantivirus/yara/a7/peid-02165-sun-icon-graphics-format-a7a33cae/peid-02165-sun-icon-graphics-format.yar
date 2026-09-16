rule PEiD_02165_Sun_Icon_Graphics_format_ {
  meta:
    description = "[Sun Icon Graphics format]"
    ep_only     = "false"

  strings:
    $a = "/* Format_version=1,"

  condition:
    $a
}