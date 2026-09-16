rule TTP_XOR_MULT_DOSStub_178d {
  strings:
    $key_178d = { 43 e5 [2] 37 fd [2] 70 ff [2] 37 ee [2] 79 e2 [2] 75 e8 [2] 62 e3 [2] 79 ad [2] 44 }

  condition:
    any of them
}