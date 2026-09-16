rule TTP_XOR_MULT_DOSStub_b9bb {
  strings:
    $key_b9bb = { ed d3 [2] 99 cb [2] de c9 [2] 99 d8 [2] d7 d4 [2] db de [2] cc d5 [2] d7 9b [2] ea }

  condition:
    any of them
}