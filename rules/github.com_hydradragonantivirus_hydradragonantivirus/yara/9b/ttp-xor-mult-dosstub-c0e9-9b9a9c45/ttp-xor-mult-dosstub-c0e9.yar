rule TTP_XOR_MULT_DOSStub_c0e9 {
  strings:
    $key_c0e9 = { 94 81 [2] e0 99 [2] a7 9b [2] e0 8a [2] ae 86 [2] a2 8c [2] b5 87 [2] ae c9 [2] 93 }

  condition:
    any of them
}