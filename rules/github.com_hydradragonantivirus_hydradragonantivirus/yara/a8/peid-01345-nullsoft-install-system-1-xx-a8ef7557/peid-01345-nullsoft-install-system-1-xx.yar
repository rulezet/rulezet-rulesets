rule PEiD_01345_Nullsoft_Install_System_1_xx_ {
  meta:
    description = "[Nullsoft Install System 1.xx]"
    ep_only     = "false"

  strings:
    $a = { 83 EC 0C 53 56 57 FF 15 20 71 40 00 05 E8 03 00 00 BE 60 FD 41 00 89 44 24 10 B3 20 FF 15 28 70 40 00 68 00 04 00 00 FF 15 28 71 40 00 50 56 FF 15 08 71 40 00 80 3D 60 FD 41 00 22 75 08 80 C3 02 BE 61 FD 41 00 8A 06 8B 3D F0 71 40 00 84 C0 74 0F 3A C3 74 }

  condition:
    $a
}