rule TTP_XOR_MULT_DOSStub_3a9c {
  strings:
    $key_3a9c = { 6e f4 [2] 1a ec [2] 5d ee [2] 1a ff [2] 54 f3 [2] 58 f9 [2] 4f f2 [2] 54 bc [2] 69 }

  condition:
    any of them
}