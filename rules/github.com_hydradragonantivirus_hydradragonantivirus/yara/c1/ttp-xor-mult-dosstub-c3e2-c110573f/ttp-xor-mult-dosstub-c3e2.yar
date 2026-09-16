rule TTP_XOR_MULT_DOSStub_c3e2 {
  strings:
    $key_c3e2 = { 97 8a [2] e3 92 [2] a4 90 [2] e3 81 [2] ad 8d [2] a1 87 [2] b6 8c [2] ad c2 [2] 90 }

  condition:
    any of them
}