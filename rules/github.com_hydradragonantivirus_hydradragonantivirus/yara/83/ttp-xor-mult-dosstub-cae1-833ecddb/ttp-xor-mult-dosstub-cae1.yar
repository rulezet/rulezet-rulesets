rule TTP_XOR_MULT_DOSStub_cae1 {
  strings:
    $key_cae1 = { 9e 89 [2] ea 91 [2] ad 93 [2] ea 82 [2] a4 8e [2] a8 84 [2] bf 8f [2] a4 c1 [2] 99 }

  condition:
    any of them
}