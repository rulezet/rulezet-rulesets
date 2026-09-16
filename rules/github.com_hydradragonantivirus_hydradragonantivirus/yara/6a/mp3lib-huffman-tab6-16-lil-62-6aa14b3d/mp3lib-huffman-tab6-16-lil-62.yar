rule mp3lib_huffman_tab6__16_lil_62_ {
  strings:
    $a0 = { E7 FF ED FF F3 FF F7 FF FB FF FD FF FF FF 33 00 03 00 23 00 FF FF 32 00 30 00 FF FF 13 00 31 00 FD FF FF FF 22 00 02 00 12 00 FD FF FF FF 21 00 20 00 01 00 FF FF 11 00 FF FF 10 00 00 00 }

  condition:
    $a0
}