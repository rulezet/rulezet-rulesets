rule TTP_XOR_MULT_DOSStub_c849 {
  strings:
    $key_c849 = { 9c 21 [2] e8 39 [2] af 3b [2] e8 2a [2] a6 26 [2] aa 2c [2] bd 27 [2] a6 69 [2] 9b }

  condition:
    any of them
}