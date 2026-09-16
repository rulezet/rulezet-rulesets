rule mp3lib_huffman_tab_c1__16_big_62_ {
  strings:
    $a0 = { FF F1 FF F9 FF FD FF FF 00 0F 00 0E FF FF 00 0D 00 0C FF FD FF FF 00 0B 00 0A FF FF 00 09 00 08 FF F9 FF FD FF FF 00 07 00 06 FF FF 00 05 00 04 FF FD FF FF 00 03 00 02 FF FF 00 01 00 00 }

  condition:
    $a0
}