rule libmpdemux_tivo_Series2AudioWithPTS__32_big_24_ {
  strings:
    $a0 = { 00 00 01 60 00 00 01 90 00 00 01 f0 00 00 02 50 00 00 03 10 00 00 03 70 }

  condition:
    $a0
}