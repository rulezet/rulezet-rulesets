rule TTP_XOR_MULT_DOSStub_c4e9 {
  strings:
    $key_c4e9 = { 90 81 [2] e4 99 [2] a3 9b [2] e4 8a [2] aa 86 [2] a6 8c [2] b1 87 [2] aa c9 [2] 97 }

  condition:
    any of them
}