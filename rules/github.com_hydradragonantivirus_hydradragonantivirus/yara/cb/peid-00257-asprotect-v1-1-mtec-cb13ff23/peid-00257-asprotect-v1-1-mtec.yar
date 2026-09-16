rule PEiD_00257_ASProtect_v1_1_MTEc_ {
  meta:
    description = "[ASProtect v1.1 MTEc]"
    ep_only     = "true"

  strings:
    $a = { 90 60 E8 1B ?? ?? ?? E9 FC }

  condition:
    $a
}