rule TTP_XOR_MULT_DOSStub_ca16 {
  strings:
    $key_ca16 = { 9e 7e [2] ea 66 [2] ad 64 [2] ea 75 [2] a4 79 [2] a8 73 [2] bf 78 [2] a4 36 [2] 99 }

  condition:
    any of them
}