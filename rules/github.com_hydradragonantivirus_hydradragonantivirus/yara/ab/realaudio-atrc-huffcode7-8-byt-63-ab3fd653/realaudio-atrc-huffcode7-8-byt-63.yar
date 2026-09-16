rule RealAudio_ATRC_huffcode7__8_byt_63_ {
  strings:
    $a0 = { 00 02 03 08 09 0a 0b 0c 0d 0e 0f 10 11 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 ec ed ee ef f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff }

  condition:
    $a0
}