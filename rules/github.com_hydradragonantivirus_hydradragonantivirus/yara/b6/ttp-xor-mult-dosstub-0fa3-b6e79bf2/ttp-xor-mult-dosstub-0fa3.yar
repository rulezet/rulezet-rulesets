rule TTP_XOR_MULT_DOSStub_0fa3 {
  strings:
    $key_0fa3 = { 5b cb [2] 2f d3 [2] 68 d1 [2] 2f c0 [2] 61 cc [2] 6d c6 [2] 7a cd [2] 61 83 [2] 5c }

  condition:
    any of them
}