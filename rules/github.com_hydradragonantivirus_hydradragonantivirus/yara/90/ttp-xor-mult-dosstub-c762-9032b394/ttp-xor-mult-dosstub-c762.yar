rule TTP_XOR_MULT_DOSStub_c762 {
  strings:
    $key_c762 = { 93 0a [2] e7 12 [2] a0 10 [2] e7 01 [2] a9 0d [2] a5 07 [2] b2 0c [2] a9 42 [2] 94 }

  condition:
    any of them
}