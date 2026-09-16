rule TTP_XOR_MULT_DOSStub_c009 {
  strings:
    $key_c009 = { 94 61 [2] e0 79 [2] a7 7b [2] e0 6a [2] ae 66 [2] a2 6c [2] b5 67 [2] ae 29 [2] 93 }

  condition:
    any of them
}