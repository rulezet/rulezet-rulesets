rule TTP_XOR_MULT_DOSStub_229c {
  strings:
    $key_229c = { 76 f4 [2] 02 ec [2] 45 ee [2] 02 ff [2] 4c f3 [2] 40 f9 [2] 57 f2 [2] 4c bc [2] 71 }

  condition:
    any of them
}