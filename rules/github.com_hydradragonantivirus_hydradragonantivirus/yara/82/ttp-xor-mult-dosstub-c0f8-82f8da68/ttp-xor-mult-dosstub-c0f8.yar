rule TTP_XOR_MULT_DOSStub_c0f8 {
  strings:
    $key_c0f8 = { 94 90 [2] e0 88 [2] a7 8a [2] e0 9b [2] ae 97 [2] a2 9d [2] b5 96 [2] ae d8 [2] 93 }

  condition:
    any of them
}