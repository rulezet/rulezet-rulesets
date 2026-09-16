rule PEiD_00187_Armadillo_v4_00_0053____Silicon_Realms_Toolworks_ {
  meta:
    description = "[Armadillo v4.00.0053 -> Silicon Realms Toolworks]"
    ep_only     = "false"

  strings:
    $a = { 55 8B EC 6A FF 68 20 8B 4B 00 68 80 E4 48 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 31 4B 00 33 D2 8A D4 89 15 A4 A1 4B 00 8B C8 81 E1 FF 00 00 00 89 0D A0 A1 4B 00 C1 E1 08 03 CA 89 0D 9C A1 4B 00 C1 E8 10 A3 98 A1 4B 00 33 F6 56 E8 78 16 00 00 59 85 C0 75 08 6A 1C E8 B0 00 00 00 59 89 75 FC E8 43 13 00 00 FF 15 8C 30 4B 00 A3 A4 B7 4B 00 E8 01 12 00 00 A3 F8 A1 4B 00 E8 AA 0F 00 00 E8 EC 0E 00 00 E8 2D FA FF FF 89 }

  condition:
    $a
}