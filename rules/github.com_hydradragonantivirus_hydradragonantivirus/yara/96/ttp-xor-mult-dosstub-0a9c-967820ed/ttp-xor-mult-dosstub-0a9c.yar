rule TTP_XOR_MULT_DOSStub_0a9c {
  strings:
    $key_0a9c = { 5e f4 [2] 2a ec [2] 6d ee [2] 2a ff [2] 64 f3 [2] 68 f9 [2] 7f f2 [2] 64 bc [2] 59 }

  condition:
    any of them
}