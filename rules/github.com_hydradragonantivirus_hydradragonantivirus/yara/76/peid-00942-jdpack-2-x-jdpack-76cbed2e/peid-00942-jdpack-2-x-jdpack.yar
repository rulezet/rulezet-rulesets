rule PEiD_00942_JDPack_2_x____JDPack_ {
  meta:
    description = "[JDPack 2.x -> JDPack]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00 }

  condition:
    $a
}