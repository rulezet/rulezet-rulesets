rule TTP_XOR_MULT_DOSStub_718d {
  strings:
    $key_718d = { 25 e5 [2] 51 fd [2] 16 ff [2] 51 ee [2] 1f e2 [2] 13 e8 [2] 04 e3 [2] 1f ad [2] 22 }

  condition:
    any of them
}