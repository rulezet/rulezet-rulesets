rule TTP_XOR_MULT_DOSStub_ca34 {
  strings:
    $key_ca34 = { 9e 5c [2] ea 44 [2] ad 46 [2] ea 57 [2] a4 5b [2] a8 51 [2] bf 5a [2] a4 14 [2] 99 }

  condition:
    any of them
}