rule TTP_XOR_MULT_DOSStub_ca61 {
  strings:
    $key_ca61 = { 9e 09 [2] ea 11 [2] ad 13 [2] ea 02 [2] a4 0e [2] a8 04 [2] bf 0f [2] a4 41 [2] 99 }

  condition:
    any of them
}