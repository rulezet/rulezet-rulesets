rule PEiD_00264_ASProtect_v1_2x_ {
  meta:
    description = "[ASProtect v1.2x]"
    ep_only     = "true"

  strings:
    $a = { 00 00 68 01 ?? ?? ?? C3 AA }

  condition:
    $a
}