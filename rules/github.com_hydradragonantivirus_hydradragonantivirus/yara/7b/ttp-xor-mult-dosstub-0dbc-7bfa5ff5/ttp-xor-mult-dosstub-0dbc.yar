rule TTP_XOR_MULT_DOSStub_0dbc {
  strings:
    $key_0dbc = { 59 d4 [2] 2d cc [2] 6a ce [2] 2d df [2] 63 d3 [2] 6f d9 [2] 78 d2 [2] 63 9c [2] 5e }

  condition:
    any of them
}