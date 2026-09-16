rule TTP_XOR_MULT_DOSStub_138d {
  strings:
    $key_138d = { 47 e5 [2] 33 fd [2] 74 ff [2] 33 ee [2] 7d e2 [2] 71 e8 [2] 66 e3 [2] 7d ad [2] 40 }

  condition:
    any of them
}