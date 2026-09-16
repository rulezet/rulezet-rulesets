rule TTP_XOR_MULT_DOSStub_ca67 {
  strings:
    $key_ca67 = { 9e 0f [2] ea 17 [2] ad 15 [2] ea 04 [2] a4 08 [2] a8 02 [2] bf 09 [2] a4 47 [2] 99 }

  condition:
    any of them
}