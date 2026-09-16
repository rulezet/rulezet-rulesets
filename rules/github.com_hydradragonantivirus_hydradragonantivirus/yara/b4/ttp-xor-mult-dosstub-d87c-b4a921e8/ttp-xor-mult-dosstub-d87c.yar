rule TTP_XOR_MULT_DOSStub_d87c {
  strings:
    $key_d87c = { 8c 14 [2] f8 0c [2] bf 0e [2] f8 1f [2] b6 13 [2] ba 19 [2] ad 12 [2] b6 5c [2] 8b }

  condition:
    any of them
}