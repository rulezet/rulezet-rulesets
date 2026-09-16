rule TTP_XOR_MULT_DOSStub_c845 {
  strings:
    $key_c845 = { 9c 2d [2] e8 35 [2] af 37 [2] e8 26 [2] a6 2a [2] aa 20 [2] bd 2b [2] a6 65 [2] 9b }

  condition:
    any of them
}