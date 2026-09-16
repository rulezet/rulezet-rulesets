rule mp3lib_huffman_tab5__16_lil_62_ {
  strings:
    $a0 = { E3 FF E7 FF E9 FF F1 FF F9 FF FB FF FD FF FF FF 33 00 23 00 32 00 31 00 FD FF FF FF 13 00 03 00 FF FF 30 00 22 00 FD FF FF FF 12 00 21 00 FF FF 02 00 20 00 11 00 FF FF 01 00 10 00 00 00 }

  condition:
    $a0
}