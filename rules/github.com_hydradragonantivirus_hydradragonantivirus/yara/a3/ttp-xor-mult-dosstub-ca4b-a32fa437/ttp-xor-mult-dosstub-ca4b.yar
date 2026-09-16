rule TTP_XOR_MULT_DOSStub_ca4b {
  strings:
    $key_ca4b = { 9e 23 [2] ea 3b [2] ad 39 [2] ea 28 [2] a4 24 [2] a8 2e [2] bf 25 [2] a4 6b [2] 99 }

  condition:
    any of them
}