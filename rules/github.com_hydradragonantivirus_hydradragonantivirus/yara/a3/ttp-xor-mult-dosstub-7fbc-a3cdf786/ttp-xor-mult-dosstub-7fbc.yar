rule TTP_XOR_MULT_DOSStub_7fbc {
  strings:
    $key_7fbc = { 2b d4 [2] 5f cc [2] 18 ce [2] 5f df [2] 11 d3 [2] 1d d9 [2] 0a d2 [2] 11 9c [2] 2c }

  condition:
    any of them
}