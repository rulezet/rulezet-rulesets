rule TTP_XOR_MULT_DOSStub_c808 {
  strings:
    $key_c808 = { 9c 60 [2] e8 78 [2] af 7a [2] e8 6b [2] a6 67 [2] aa 6d [2] bd 66 [2] a6 28 [2] 9b }

  condition:
    any of them
}