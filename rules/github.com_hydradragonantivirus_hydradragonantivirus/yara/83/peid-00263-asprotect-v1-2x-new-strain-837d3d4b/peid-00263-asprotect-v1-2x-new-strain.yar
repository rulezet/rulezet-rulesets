rule PEiD_00263_ASProtect_v1_2x__New_Strain__ {
  meta:
    description = "[ASProtect v1.2x (New Strain)]"
    ep_only     = "true"

  strings:
    $a = { 68 01 ?? ?? ?? E8 01 ?? ?? ?? C3 C3 }

  condition:
    $a
}