rule PEiD_02229_Themida_1_0_x_x___1_8_x_x__no_compression_____Oreans_Technologies__h__ {
  meta:
    description = "[Themida 1.0.x.x - 1.8.x.x (no compression) -> Oreans Technologies (h)]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 83 C4 D8 60 E8 00 00 00 00 5A 81 EA ?? ?? ?? ?? 8B DA C7 45 D8 00 00 00 00 8B 45 D8 40 89 45 D8 81 7D D8 80 00 00 00 74 0F 8B 45 08 89 83 ?? ?? ?? ?? FF 45 08 43 EB E1 89 45 DC 61 8B 45 DC C9 C2 04 00 55 8B EC 81 C4 7C FF FF FF 60 E8 00 00 00 00 }

  condition:
    $a
}