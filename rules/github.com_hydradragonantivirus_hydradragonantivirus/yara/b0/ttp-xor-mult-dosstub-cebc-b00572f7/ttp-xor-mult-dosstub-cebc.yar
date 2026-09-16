rule TTP_XOR_MULT_DOSStub_cebc {
  strings:
    $key_cebc = { 9a d4 [2] ee cc [2] a9 ce [2] ee df [2] a0 d3 [2] ac d9 [2] bb d2 [2] a0 9c [2] 9d }

  condition:
    any of them
}