rule TTP_XOR_MULT_DOSStub_c863 {
  strings:
    $key_c863 = { 9c 0b [2] e8 13 [2] af 11 [2] e8 00 [2] a6 0c [2] aa 06 [2] bd 0d [2] a6 43 [2] 9b }

  condition:
    any of them
}