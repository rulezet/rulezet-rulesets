rule TTP_XOR_MULT_DOSStub_ca18 {
  strings:
    $key_ca18 = { 9e 70 [2] ea 68 [2] ad 6a [2] ea 7b [2] a4 77 [2] a8 7d [2] bf 76 [2] a4 38 [2] 99 }

  condition:
    any of them
}