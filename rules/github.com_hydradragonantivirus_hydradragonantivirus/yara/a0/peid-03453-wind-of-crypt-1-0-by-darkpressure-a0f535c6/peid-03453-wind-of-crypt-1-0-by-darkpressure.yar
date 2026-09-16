rule PEiD_03453_Wind_of_Crypt_1_0___by_DarkPressure_ {
  meta:
    description = "[Wind of Crypt 1.0 - by DarkPressure]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 EC 53 ?? ?? ?? ?? 89 45 EC B8 64 40 00 10 E8 28 EA FF FF 33 C0 55 68 CE 51 00 10 64 ?? ?? ?? ?? 20 6A 00 68 80 00 00 00 6A 03 6A 00 6A 01 68 00 00 00 80 8D 55 EC 33 C0 E8 F6 DB FF FF 8B 45 EC E8 12 E7 FF FF 50 E8 3C EA FF FF 8B D8 83 FB FF }

  condition:
    $a
}