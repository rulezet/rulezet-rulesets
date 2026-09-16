rule TTP_XOR_MULT_DOSStub_c3e5 {
  strings:
    $key_c3e5 = { 97 8d [2] e3 95 [2] a4 97 [2] e3 86 [2] ad 8a [2] a1 80 [2] b6 8b [2] ad c5 [2] 90 }

  condition:
    any of them
}