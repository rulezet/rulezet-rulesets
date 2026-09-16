rule MMX_codes__32_lil_124_ {
  strings:
    $a0 = { 85 27 00 3f 8b 66 01 3f 5b f4 03 3f 68 f2 07 3f 38 98 0d 3f 3a 3b 15 3f 6e 5c 1f 3f 3d c0 2c 3f ee 99 3e 3f 9e df 56 3f 3b fa 78 3f 35 b0 95 3f 1b f9 bd 3f af b2 03 40 42 16 5a 40 46 0a 23 41 8d 9e 00 3f 78 c2 05 3f 3f 23 11 3f 1d 96 25 3f 80 c4 49 3f 49 c4 87 3f 26 79 dc 3f 9c 3c a3 40 f7 81 02 3f bd f1 19 3f d7 64 66 3f cf 06 24 40 d4 8b 0a 3f 75 3d a7 3f f3 04 35 3f }

  condition:
    $a0
}