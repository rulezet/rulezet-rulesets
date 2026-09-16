rule TTP_XOR_MULT_DOSStub_5fa3 {
  strings:
    $key_5fa3 = { 0b cb [2] 7f d3 [2] 38 d1 [2] 7f c0 [2] 31 cc [2] 3d c6 [2] 2a cd [2] 31 83 [2] 0c }

  condition:
    any of them
}