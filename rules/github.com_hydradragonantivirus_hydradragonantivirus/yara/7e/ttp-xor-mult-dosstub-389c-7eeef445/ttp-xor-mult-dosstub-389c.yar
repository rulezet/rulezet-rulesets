rule TTP_XOR_MULT_DOSStub_389c {
  strings:
    $key_389c = { 6c f4 [2] 18 ec [2] 5f ee [2] 18 ff [2] 56 f3 [2] 5a f9 [2] 4d f2 [2] 56 bc [2] 6b }

  condition:
    any of them
}