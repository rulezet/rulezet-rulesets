rule TTP_XOR_MULT_DOSStub_c864 {
  strings:
    $key_c864 = { 9c 0c [2] e8 14 [2] af 16 [2] e8 07 [2] a6 0b [2] aa 01 [2] bd 0a [2] a6 44 [2] 9b }

  condition:
    any of them
}