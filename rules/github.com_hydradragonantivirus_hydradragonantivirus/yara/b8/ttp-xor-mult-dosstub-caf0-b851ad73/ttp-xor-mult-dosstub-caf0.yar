rule TTP_XOR_MULT_DOSStub_caf0 {
  strings:
    $key_caf0 = { 9e 98 [2] ea 80 [2] ad 82 [2] ea 93 [2] a4 9f [2] a8 95 [2] bf 9e [2] a4 d0 [2] 99 }

  condition:
    any of them
}