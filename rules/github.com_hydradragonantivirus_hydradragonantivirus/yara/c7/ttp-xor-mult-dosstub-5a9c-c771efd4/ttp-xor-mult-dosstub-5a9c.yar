rule TTP_XOR_MULT_DOSStub_5a9c {
  strings:
    $key_5a9c = { 0e f4 [2] 7a ec [2] 3d ee [2] 7a ff [2] 34 f3 [2] 38 f9 [2] 2f f2 [2] 34 bc [2] 09 }

  condition:
    any of them
}