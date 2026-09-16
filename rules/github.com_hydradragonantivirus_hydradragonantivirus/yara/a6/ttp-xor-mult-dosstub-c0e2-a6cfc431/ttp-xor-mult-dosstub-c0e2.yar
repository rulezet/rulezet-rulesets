rule TTP_XOR_MULT_DOSStub_c0e2 {
  strings:
    $key_c0e2 = { 94 8a [2] e0 92 [2] a7 90 [2] e0 81 [2] ae 8d [2] a2 87 [2] b5 8c [2] ae c2 [2] 93 }

  condition:
    any of them
}