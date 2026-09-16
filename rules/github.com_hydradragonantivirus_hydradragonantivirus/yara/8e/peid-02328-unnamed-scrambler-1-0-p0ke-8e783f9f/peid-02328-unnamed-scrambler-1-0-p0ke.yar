rule PEiD_02328_Unnamed_Scrambler_1_0____p0ke_ {
  meta:
    description = "[Unnamed Scrambler 1.0 -> p0ke]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 EC 53 56 33 C0 89 45 ?? ?? ?? ?? 40 00 E8 11 F4 FF FF BE 30 6B 40 00 33 C0 55 68 C9 42 40 00 64 FF 30 64 89 20 E8 C9 FA FF FF BA D8 42 40 00 8B ?? ?? ?? ?? FF FF 8B D8 B8 28 6B 40 00 8B 16 E8 37 F0 FF FF B8 2C 6B 40 00 8B 16 E8 2B F0 FF FF }

  condition:
    $a
}