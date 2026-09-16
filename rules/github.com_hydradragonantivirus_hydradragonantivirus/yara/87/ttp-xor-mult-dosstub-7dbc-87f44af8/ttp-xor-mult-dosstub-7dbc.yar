rule TTP_XOR_MULT_DOSStub_7dbc {
  strings:
    $key_7dbc = { 29 d4 [2] 5d cc [2] 1a ce [2] 5d df [2] 13 d3 [2] 1f d9 [2] 08 d2 [2] 13 9c [2] 2e }

  condition:
    any of them
}