rule mp3lib_huffman_tab_c1__16_lil_62_ {
  strings:
    $a0 = { F1 FF F9 FF FD FF FF FF 0F 00 0E 00 FF FF 0D 00 0C 00 FD FF FF FF 0B 00 0A 00 FF FF 09 00 08 00 F9 FF FD FF FF FF 07 00 06 00 FF FF 05 00 04 00 FD FF FF FF 03 00 02 00 FF FF 01 00 00 00 }

  condition:
    $a0
}