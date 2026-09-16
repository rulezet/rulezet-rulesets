rule PEiD_00746_FreeJoiner_Small__build_014_015_____GlOFF_ {
  meta:
    description = "[FreeJoiner Small (build 014/015) -> GlOFF]"
    ep_only     = "true"

  strings:
    $a = { E8 0E FE FF FF 6A 00 E8 0D 00 00 00 CC FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10 40 00 FF 25 90 10 40 00 FF 25 94 10 40 00 FF 25 98 10 40 00 FF 25 9C 10 40 00 FF 25 A0 10 40 00 FF 25 A4 10 40 00 FF 25 AC 10 40 00 }

  condition:
    $a
}