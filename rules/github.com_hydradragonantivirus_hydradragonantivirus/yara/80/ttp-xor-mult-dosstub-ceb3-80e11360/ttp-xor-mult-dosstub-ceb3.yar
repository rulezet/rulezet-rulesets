rule TTP_XOR_MULT_DOSStub_ceb3 {
  strings:
    $key_ceb3 = { 9a db [2] ee c3 [2] a9 c1 [2] ee d0 [2] a0 dc [2] ac d6 [2] bb dd [2] a0 93 [2] 9d }

  condition:
    any of them
}