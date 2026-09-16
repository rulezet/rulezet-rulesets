rule TTP_XOR_MULT_DOSStub_ca25 {
  strings:
    $key_ca25 = { 9e 4d [2] ea 55 [2] ad 57 [2] ea 46 [2] a4 4a [2] a8 40 [2] bf 4b [2] a4 05 [2] 99 }

  condition:
    any of them
}