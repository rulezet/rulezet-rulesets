rule TTP_XOR_MULT_DOSStub_ca26 {
  strings:
    $key_ca26 = { 9e 4e [2] ea 56 [2] ad 54 [2] ea 45 [2] a4 49 [2] a8 43 [2] bf 48 [2] a4 06 [2] 99 }

  condition:
    any of them
}