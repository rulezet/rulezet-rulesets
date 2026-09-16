rule PEiD_00581_EXE_Stealth_v2_72_ {
  meta:
    description = "[EXE Stealth v2.72]"
    ep_only     = "true"

  strings:
    $a = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 }

  condition:
    $a
}