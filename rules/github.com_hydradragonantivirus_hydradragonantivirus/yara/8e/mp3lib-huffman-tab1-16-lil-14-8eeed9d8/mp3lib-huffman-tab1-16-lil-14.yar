rule mp3lib_huffman_tab1__16_lil_14_ {
  strings:
    $a0 = { FB FF FD FF FF FF 11 00 01 00 10 00 00 00 }

  condition:
    $a0
}