rule libavcodec_AC3_vq_hebap1__16_big_48_ {
  strings:
    $a0 = { 1B FF 12 83 04 52 10 AD 28 AC 12 D4 E9 BA F3 8D C7 6D FA 90 F8 15 03 51 02 79 18 37 1B 61 CE 15 F6 FE F5 B4 FA 44 E4 89 1D A8 29 79 E8 C6 F4 0A }

  condition:
    $a0
}