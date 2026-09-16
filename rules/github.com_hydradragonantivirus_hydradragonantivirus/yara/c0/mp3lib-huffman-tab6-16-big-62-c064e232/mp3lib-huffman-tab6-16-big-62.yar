rule mp3lib_huffman_tab6__16_big_62_ {
  strings:
    $a0 = { FF E7 FF ED FF F3 FF F7 FF FB FF FD FF FF 00 33 00 03 00 23 FF FF 00 32 00 30 FF FF 00 13 00 31 FF FD FF FF 00 22 00 02 00 12 FF FD FF FF 00 21 00 20 00 01 FF FF 00 11 FF FF 00 10 00 00 }

  condition:
    $a0
}