rule TTP_XOR_MULT_DOSStub_c302 {
  strings:
    $key_c302 = { 97 6a [2] e3 72 [2] a4 70 [2] e3 61 [2] ad 6d [2] a1 67 [2] b6 6c [2] ad 22 [2] 90 }

  condition:
    any of them
}