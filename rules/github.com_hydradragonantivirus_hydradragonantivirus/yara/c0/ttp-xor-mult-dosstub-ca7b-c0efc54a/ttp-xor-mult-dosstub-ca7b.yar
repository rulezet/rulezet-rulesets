rule TTP_XOR_MULT_DOSStub_ca7b {
  strings:
    $key_ca7b = { 9e 13 [2] ea 0b [2] ad 09 [2] ea 18 [2] a4 14 [2] a8 1e [2] bf 15 [2] a4 5b [2] 99 }

  condition:
    any of them
}