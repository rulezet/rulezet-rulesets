rule TTP_XOR_MULT_DOSStub_218d {
  strings:
    $key_218d = { 75 e5 [2] 01 fd [2] 46 ff [2] 01 ee [2] 4f e2 [2] 43 e8 [2] 54 e3 [2] 4f ad [2] 72 }

  condition:
    any of them
}