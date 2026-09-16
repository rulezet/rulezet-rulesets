rule PEiD_01031_MicroJoiner_1_5____coban2k_ {
  meta:
    description = "[MicroJoiner 1.5 -> coban2k]"
    ep_only     = "true"

  strings:
    $a = { BF 05 10 40 00 83 EC 30 8B EC E8 C8 FF FF FF E8 C3 FF FF FF }

  condition:
    $a
}