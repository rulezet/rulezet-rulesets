rule TTP_XOR_MULT_DOSStub_588d {
  strings:
    $key_588d = { 0c e5 [2] 78 fd [2] 3f ff [2] 78 ee [2] 36 e2 [2] 3a e8 [2] 2d e3 [2] 36 ad [2] 0b }

  condition:
    any of them
}