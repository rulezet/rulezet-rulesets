rule PEiD_01049_Microsoft_Resource_Cursors_file_ {
  meta:
    description = "[Microsoft Resource Cursors file]"
    ep_only     = "false"

  strings:
    $a = { 00 00 02 00 01 00 20 20 00 00 ?? 00 ?? 00 E8 02 00 00 16 }

  condition:
    $a
}