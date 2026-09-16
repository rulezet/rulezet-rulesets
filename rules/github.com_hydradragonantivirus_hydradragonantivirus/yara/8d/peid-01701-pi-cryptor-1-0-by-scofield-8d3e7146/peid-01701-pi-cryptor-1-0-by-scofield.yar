rule PEiD_01701_Pi_Cryptor_1_0___by_Scofield_ {
  meta:
    description = "[Pi Cryptor 1.0 - by Scofield]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 EC 53 56 57 31 C0 89 45 EC B8 40 1E 06 00 E8 48 FA FF FF 33 C0 55 68 36 1F 06 00 64 FF 30 64 89 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 31 C0 E8 4E F4 FF FF 8B 45 EC E8 F6 F7 FF FF 50 E8 CC FA FF FF 8B D8 83 FB FF }

  condition:
    $a
}