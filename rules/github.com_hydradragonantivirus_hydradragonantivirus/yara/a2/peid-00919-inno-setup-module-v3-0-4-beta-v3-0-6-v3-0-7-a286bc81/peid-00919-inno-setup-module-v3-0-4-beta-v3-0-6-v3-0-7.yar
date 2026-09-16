rule PEiD_00919_Inno_Setup_Module_v3_0_4_beta_v3_0_6_v3_0_7_ {
  meta:
    description = "[Inno Setup Module v3.0.4-beta/v3.0.6/v3.0.7]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

  condition:
    $a
}