rule PEiD_00445_CRYPToCRACk_s_PE_Protector_v0_9_3____Lucas_Fleischer__h__ {
  meta:
    description = "[CRYPToCRACk's PE Protector v0.9.3 -> Lucas Fleischer (h)]"
    ep_only     = "true"

  strings:
    $a = { 5B 81 E3 00 FF FF FF 66 81 3B 4D 5A 75 33 8B F3 03 73 3C 81 3E 50 45 00 00 75 26 0F B7 46 18 8B C8 69 C0 AD 0B 00 00 F7 E0 2D AB 5D 41 4B 69 C9 DE C0 00 00 03 C1 75 09 83 EC 04 0F 85 DD 00 00 00 81 EB 00 01 00 00 75 BE 90 72 ?? ?? ?? ?? 00 00 00 00 00 00 00 7A ?? ?? ?? 72 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 C1 00 46 61 74 61 6C 45 78 69 74 }

  condition:
    $a
}