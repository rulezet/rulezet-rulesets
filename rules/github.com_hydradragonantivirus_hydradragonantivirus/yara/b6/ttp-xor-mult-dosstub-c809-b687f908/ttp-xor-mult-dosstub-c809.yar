rule TTP_XOR_MULT_DOSStub_c809 {
  strings:
    $key_c809 = { 9c 61 [2] e8 79 [2] af 7b [2] e8 6a [2] a6 66 [2] aa 6c [2] bd 67 [2] a6 29 [2] 9b }

  condition:
    any of them
}