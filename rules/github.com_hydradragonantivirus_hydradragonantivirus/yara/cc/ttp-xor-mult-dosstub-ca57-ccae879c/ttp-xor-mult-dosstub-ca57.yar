rule TTP_XOR_MULT_DOSStub_ca57 {
  strings:
    $key_ca57 = { 9e 3f [2] ea 27 [2] ad 25 [2] ea 34 [2] a4 38 [2] a8 32 [2] bf 39 [2] a4 77 [2] 99 }

  condition:
    any of them
}