rule TTP_XOR_MULT_DOSStub_caa2 {
  strings:
    $key_caa2 = { 9e ca [2] ea d2 [2] ad d0 [2] ea c1 [2] a4 cd [2] a8 c7 [2] bf cc [2] a4 82 [2] 99 }

  condition:
    any of them
}