rule TTP_XOR_MULT_DOSStub_dfbc {
  strings:
    $key_dfbc = { 8b d4 [2] ff cc [2] b8 ce [2] ff df [2] b1 d3 [2] bd d9 [2] aa d2 [2] b1 9c [2] 8c }

  condition:
    any of them
}