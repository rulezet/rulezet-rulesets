rule TTP_XOR_MULT_DOSStub_1a9c {
  strings:
    $key_1a9c = { 4e f4 [2] 3a ec [2] 7d ee [2] 3a ff [2] 74 f3 [2] 78 f9 [2] 6f f2 [2] 74 bc [2] 49 }

  condition:
    any of them
}