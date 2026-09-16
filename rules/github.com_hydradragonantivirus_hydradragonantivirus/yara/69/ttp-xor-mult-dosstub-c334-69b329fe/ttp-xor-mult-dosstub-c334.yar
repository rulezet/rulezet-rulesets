rule TTP_XOR_MULT_DOSStub_c334 {
  strings:
    $key_c334 = { 97 5c [2] e3 44 [2] a4 46 [2] e3 57 [2] ad 5b [2] a1 51 [2] b6 5a [2] ad 14 [2] 90 }

  condition:
    any of them
}