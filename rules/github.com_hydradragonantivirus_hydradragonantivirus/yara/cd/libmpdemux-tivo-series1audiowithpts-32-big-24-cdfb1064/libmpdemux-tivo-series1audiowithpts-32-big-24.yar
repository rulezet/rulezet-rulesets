rule libmpdemux_tivo_Series1AudioWithPTS__32_big_24_ {
  strings:
    $a0 = { 00 00 01 5b 00 00 01 8b 00 00 01 eb 00 00 02 4b 00 00 03 0b 00 00 03 6b }

  condition:
    $a0
}