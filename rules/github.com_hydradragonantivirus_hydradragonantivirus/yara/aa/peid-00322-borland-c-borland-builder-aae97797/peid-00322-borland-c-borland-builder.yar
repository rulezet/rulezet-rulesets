rule PEiD_00322_Borland_C___Borland_Builder_ {
  meta:
    description = "[Borland C / Borland Builder]"
    ep_only     = "false"

  strings:
    $a = { 3B CF 76 05 2B CF FC F3 AA 59 }

  condition:
    $a
}