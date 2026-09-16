rule TTP_XOR_MULT_DOSStub_d9bc {
  strings:
    $key_d9bc = { 8d d4 [2] f9 cc [2] be ce [2] f9 df [2] b7 d3 [2] bb d9 [2] ac d2 [2] b7 9c [2] 8a }

  condition:
    any of them
}