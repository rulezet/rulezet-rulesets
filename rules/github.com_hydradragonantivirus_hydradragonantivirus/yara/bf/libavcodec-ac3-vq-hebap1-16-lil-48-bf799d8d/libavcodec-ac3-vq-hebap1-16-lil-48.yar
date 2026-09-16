rule libavcodec_AC3_vq_hebap1__16_lil_48_ {
  strings:
    $a0 = { FF 1B 83 12 52 04 AD 10 AC 28 D4 12 BA E9 8D F3 6D C7 90 FA 15 F8 51 03 79 02 37 18 61 1B 15 CE FE F6 B4 F5 44 FA 89 E4 A8 1D 79 29 C6 E8 0A F4 }

  condition:
    $a0
}