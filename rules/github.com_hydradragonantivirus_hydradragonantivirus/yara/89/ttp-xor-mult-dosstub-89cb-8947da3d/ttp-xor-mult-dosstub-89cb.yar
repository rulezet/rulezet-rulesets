rule TTP_XOR_MULT_DOSStub_89cb {
  strings:
    $key_89cb = { dd a3 [2] a9 bb [2] ee b9 [2] a9 a8 [2] e7 a4 [2] eb ae [2] fc a5 [2] e7 eb [2] da }

  condition:
    any of them
}