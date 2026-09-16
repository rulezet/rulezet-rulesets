rule TTP_XOR_MULT_DOSStub_ca2a {
  strings:
    $key_ca2a = { 9e 42 [2] ea 5a [2] ad 58 [2] ea 49 [2] a4 45 [2] a8 4f [2] bf 44 [2] a4 0a [2] 99 }

  condition:
    any of them
}