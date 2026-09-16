rule TTP_XOR_MULT_DOSStub_c3e9 {
  strings:
    $key_c3e9 = { 97 81 [2] e3 99 [2] a4 9b [2] e3 8a [2] ad 86 [2] a1 8c [2] b6 87 [2] ad c9 [2] 90 }

  condition:
    any of them
}