rule TTP_XOR_MULT_DOSStub_aebc {
  strings:
    $key_aebc = { fa d4 [2] 8e cc [2] c9 ce [2] 8e df [2] c0 d3 [2] cc d9 [2] db d2 [2] c0 9c [2] fd }

  condition:
    any of them
}