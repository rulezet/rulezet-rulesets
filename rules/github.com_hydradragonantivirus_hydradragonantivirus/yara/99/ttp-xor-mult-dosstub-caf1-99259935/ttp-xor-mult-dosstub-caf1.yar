rule TTP_XOR_MULT_DOSStub_caf1 {
  strings:
    $key_caf1 = { 9e 99 [2] ea 81 [2] ad 83 [2] ea 92 [2] a4 9e [2] a8 94 [2] bf 9f [2] a4 d1 [2] 99 }

  condition:
    any of them
}