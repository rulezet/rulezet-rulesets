rule TTP_XOR_MULT_DOSStub_cae2 {
  strings:
    $key_cae2 = { 9e 8a [2] ea 92 [2] ad 90 [2] ea 81 [2] a4 8d [2] a8 87 [2] bf 8c [2] a4 c2 [2] 99 }

  condition:
    any of them
}