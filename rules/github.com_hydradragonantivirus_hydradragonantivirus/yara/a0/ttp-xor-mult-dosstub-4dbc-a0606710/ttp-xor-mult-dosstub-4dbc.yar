rule TTP_XOR_MULT_DOSStub_4dbc {
  strings:
    $key_4dbc = { 19 d4 [2] 6d cc [2] 2a ce [2] 6d df [2] 23 d3 [2] 2f d9 [2] 38 d2 [2] 23 9c [2] 1e }

  condition:
    any of them
}