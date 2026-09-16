rule TTP_XOR_MULT_DOSStub_6fa3 {
  strings:
    $key_6fa3 = { 3b cb [2] 4f d3 [2] 08 d1 [2] 4f c0 [2] 01 cc [2] 0d c6 [2] 1a cd [2] 01 83 [2] 3c }

  condition:
    any of them
}