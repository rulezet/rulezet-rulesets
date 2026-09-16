rule TTP_XOR_MULT_DOSStub_ceb7 {
  strings:
    $key_ceb7 = { 9a df [2] ee c7 [2] a9 c5 [2] ee d4 [2] a0 d8 [2] ac d2 [2] bb d9 [2] a0 97 [2] 9d }

  condition:
    any of them
}