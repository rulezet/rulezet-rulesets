rule TTP_XOR_MULT_DOSStub_c3e4 {
  strings:
    $key_c3e4 = { 97 8c [2] e3 94 [2] a4 96 [2] e3 87 [2] ad 8b [2] a1 81 [2] b6 8a [2] ad c4 [2] 90 }

  condition:
    any of them
}