rule PEiD_00910_IMP_Packer_1_0____Mahdi_Hezavehi__IMPOSTER__ {
  meta:
    description = "[IMP-Packer 1.0 -> Mahdi Hezavehi [IMPOSTER]]"
    ep_only     = "false"

  strings:
    $a = { 28 ?? ?? ?? 00 00 00 00 00 00 00 00 40 ?? ?? ?? 34 ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4C ?? ?? ?? 5C ?? ?? ?? 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 47 65 74 50 72 6F 63 }

  condition:
    $a
}