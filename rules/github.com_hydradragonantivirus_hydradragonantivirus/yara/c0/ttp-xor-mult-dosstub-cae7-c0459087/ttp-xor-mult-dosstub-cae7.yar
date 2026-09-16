rule TTP_XOR_MULT_DOSStub_cae7 {
  strings:
    $key_cae7 = { 9e 8f [2] ea 97 [2] ad 95 [2] ea 84 [2] a4 88 [2] a8 82 [2] bf 89 [2] a4 c7 [2] 99 }

  condition:
    any of them
}