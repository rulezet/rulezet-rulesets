rule PEiD_00031_ACProtect_V1_3X____risco_ {
  meta:
    description = "[ACProtect V1.3X -> risco]"
    ep_only     = "true"

  strings:
    $a = { 60 50 E8 01 00 00 00 75 83 }

  condition:
    $a
}