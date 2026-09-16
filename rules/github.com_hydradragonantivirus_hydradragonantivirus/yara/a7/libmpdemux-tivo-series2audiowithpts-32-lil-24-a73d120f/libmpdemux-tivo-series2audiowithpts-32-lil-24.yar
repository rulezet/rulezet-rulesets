rule libmpdemux_tivo_Series2AudioWithPTS__32_lil_24_ {
  strings:
    $a0 = { 60 01 00 00 90 01 00 00 f0 01 00 00 50 02 00 00 10 03 00 00 70 03 00 00 }

  condition:
    $a0
}