rule TTP_XOR_MULT_DOSStub_c842 {
  strings:
    $key_c842 = { 9c 2a [2] e8 32 [2] af 30 [2] e8 21 [2] a6 2d [2] aa 27 [2] bd 2c [2] a6 62 [2] 9b }

  condition:
    any of them
}