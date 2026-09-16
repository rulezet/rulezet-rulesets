rule TTP_XOR_MULT_DOSStub_0fbc {
  strings:
    $key_0fbc = { 5b d4 [2] 2f cc [2] 68 ce [2] 2f df [2] 61 d3 [2] 6d d9 [2] 7a d2 [2] 61 9c [2] 5c }

  condition:
    any of them
}