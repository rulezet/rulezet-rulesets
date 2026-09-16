rule mp3lib_huffman_tab1__16_big_14_ {
  strings:
    $a0 = { FF FB FF FD FF FF 00 11 00 01 00 10 00 00 }

  condition:
    $a0
}