rule TTP_XOR_MULT_DOSStub_ca39 {
  strings:
    $key_ca39 = { 9e 51 [2] ea 49 [2] ad 4b [2] ea 5a [2] a4 56 [2] a8 5c [2] bf 57 [2] a4 19 [2] 99 }

  condition:
    any of them
}