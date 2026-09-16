rule TTP_XOR_MULT_DOSStub_ceb1 {
  strings:
    $key_ceb1 = { 9a d9 [2] ee c1 [2] a9 c3 [2] ee d2 [2] a0 de [2] ac d4 [2] bb df [2] a0 91 [2] 9d }

  condition:
    any of them
}