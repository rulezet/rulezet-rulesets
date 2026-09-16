rule TTP_XOR_MULT_DOSStub_c858 {
  strings:
    $key_c858 = { 9c 30 [2] e8 28 [2] af 2a [2] e8 3b [2] a6 37 [2] aa 3d [2] bd 36 [2] a6 78 [2] 9b }

  condition:
    any of them
}