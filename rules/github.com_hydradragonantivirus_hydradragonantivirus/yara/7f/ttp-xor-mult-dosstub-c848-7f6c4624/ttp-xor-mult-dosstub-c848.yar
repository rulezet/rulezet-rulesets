rule TTP_XOR_MULT_DOSStub_c848 {
  strings:
    $key_c848 = { 9c 20 [2] e8 38 [2] af 3a [2] e8 2b [2] a6 27 [2] aa 2d [2] bd 26 [2] a6 68 [2] 9b }

  condition:
    any of them
}