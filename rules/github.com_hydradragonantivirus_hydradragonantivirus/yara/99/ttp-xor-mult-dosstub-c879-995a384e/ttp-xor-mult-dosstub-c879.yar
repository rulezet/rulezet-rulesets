rule TTP_XOR_MULT_DOSStub_c879 {
  strings:
    $key_c879 = { 9c 11 [2] e8 09 [2] af 0b [2] e8 1a [2] a6 16 [2] aa 1c [2] bd 17 [2] a6 59 [2] 9b }

  condition:
    any of them
}