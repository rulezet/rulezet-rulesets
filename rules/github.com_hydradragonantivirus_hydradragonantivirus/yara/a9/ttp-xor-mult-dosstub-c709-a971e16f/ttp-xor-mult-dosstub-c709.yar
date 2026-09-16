rule TTP_XOR_MULT_DOSStub_c709 {
  strings:
    $key_c709 = { 93 61 [2] e7 79 [2] a0 7b [2] e7 6a [2] a9 66 [2] a5 6c [2] b2 67 [2] a9 29 [2] 94 }

  condition:
    any of them
}