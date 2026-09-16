rule TTP_XOR_MULT_DOSStub_ca21 {
  strings:
    $key_ca21 = { 9e 49 [2] ea 51 [2] ad 53 [2] ea 42 [2] a4 4e [2] a8 44 [2] bf 4f [2] a4 01 [2] 99 }

  condition:
    any of them
}