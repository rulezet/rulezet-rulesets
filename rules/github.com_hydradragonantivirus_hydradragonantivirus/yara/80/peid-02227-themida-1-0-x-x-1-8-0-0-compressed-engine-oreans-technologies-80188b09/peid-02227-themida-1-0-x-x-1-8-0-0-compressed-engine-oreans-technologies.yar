rule PEiD_02227_Themida_1_0_x_x___1_8_0_0__compressed_engine_____Oreans_Technologies_ {
  meta:
    description = "[Themida 1.0.x.x - 1.8.0.0 (compressed engine) -> Oreans Technologies]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? ?? ?? 60 0B C0 74 58 E8 00 00 00 00 58 05 43 00 00 00 80 38 E9 75 03 61 EB 35 E8 00 00 00 00 58 25 00 F0 FF FF 33 FF 66 BB 19 5A 66 83 C3 34 66 39 18 75 12 0F B7 50 3C 03 D0 BB E9 44 00 00 83 C3 67 39 1A 74 07 2D 00 10 00 00 EB DA 8B F8 B8 }

  condition:
    $a
}