rule PEiD_00741_FreeJoiner_1_5_3__Stub_engine_1_7_____GlOFF_ {
  meta:
    description = "[FreeJoiner 1.5.3 (Stub engine 1.7) -> GlOFF]"
    ep_only     = "true"

  strings:
    $a = { E8 33 FD FF FF 50 E8 0D 00 00 00 CC FF 25 08 20 40 00 FF 25 0C 20 40 00 FF 25 10 20 40 00 FF 25 14 20 40 00 FF 25 18 20 40 00 FF 25 1C 20 40 00 FF 25 20 20 40 00 FF 25 24 20 40 00 FF 25 28 20 40 00 FF 25 00 20 40 00 }

  condition:
    $a
}