rule TTP_XOR_MULT_DOSStub_ca12 {
  strings:
    $key_ca12 = { 9e 7a [2] ea 62 [2] ad 60 [2] ea 71 [2] a4 7d [2] a8 77 [2] bf 7c [2] a4 32 [2] 99 }

  condition:
    any of them
}