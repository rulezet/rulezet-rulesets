rule PEiD_02025_SafeDisc_4_ {
  meta:
    description = "[SafeDisc 4]"
    ep_only     = "false"

  strings:
    $a = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }

  condition:
    $a
}