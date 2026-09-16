rule TTP_XOR_MULT_DOSStub_039c {
  strings:
    $key_039c = { 57 f4 [2] 23 ec [2] 64 ee [2] 23 ff [2] 6d f3 [2] 61 f9 [2] 76 f2 [2] 6d bc [2] 50 }

  condition:
    any of them
}