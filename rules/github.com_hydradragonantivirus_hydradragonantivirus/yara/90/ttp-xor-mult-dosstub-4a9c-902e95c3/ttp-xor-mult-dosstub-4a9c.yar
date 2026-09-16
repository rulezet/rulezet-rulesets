rule TTP_XOR_MULT_DOSStub_4a9c {
  strings:
    $key_4a9c = { 1e f4 [2] 6a ec [2] 2d ee [2] 6a ff [2] 24 f3 [2] 28 f9 [2] 3f f2 [2] 24 bc [2] 19 }

  condition:
    any of them
}