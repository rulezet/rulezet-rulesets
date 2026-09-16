rule PEiD_00994_Macromedia_Windows_Flash_Projector_Player_v3_0_ {
  meta:
    description = "[Macromedia Windows Flash Projector/Player v3.0]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 EC 44 56 FF 15 94 13 42 00 8B F0 B1 22 8A 06 3A C1 75 13 8A 46 01 46 3A C1 74 04 84 C0 75 F4 38 0E 75 0D 46 EB 0A 3C 20 7E 06 }

  condition:
    $a
}