rule TTP_XOR_MULT_DOSStub_c309 {
  strings:
    $key_c309 = { 97 61 [2] e3 79 [2] a4 7b [2] e3 6a [2] ad 66 [2] a1 6c [2] b6 67 [2] ad 29 [2] 90 }

  condition:
    any of them
}