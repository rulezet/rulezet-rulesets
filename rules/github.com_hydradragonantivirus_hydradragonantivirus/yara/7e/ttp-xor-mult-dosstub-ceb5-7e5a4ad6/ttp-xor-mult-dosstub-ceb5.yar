rule TTP_XOR_MULT_DOSStub_ceb5 {
  strings:
    $key_ceb5 = { 9a dd [2] ee c5 [2] a9 c7 [2] ee d6 [2] a0 da [2] ac d0 [2] bb db [2] a0 95 [2] 9d }

  condition:
    any of them
}