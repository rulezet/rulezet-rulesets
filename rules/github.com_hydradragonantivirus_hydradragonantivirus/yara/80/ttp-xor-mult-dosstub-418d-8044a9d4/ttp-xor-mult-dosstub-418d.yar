rule TTP_XOR_MULT_DOSStub_418d {
  strings:
    $key_418d = { 15 e5 [2] 61 fd [2] 26 ff [2] 61 ee [2] 2f e2 [2] 23 e8 [2] 34 e3 [2] 2f ad [2] 12 }

  condition:
    any of them
}