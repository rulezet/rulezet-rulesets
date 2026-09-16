rule TTP_XOR_MULT_DOSStub_ecac {
  strings:
    $key_ecac = { b8 c4 [2] cc dc [2] 8b de [2] cc cf [2] 82 c3 [2] 8e c9 [2] 99 c2 [2] 82 8c [2] bf }

  condition:
    any of them
}