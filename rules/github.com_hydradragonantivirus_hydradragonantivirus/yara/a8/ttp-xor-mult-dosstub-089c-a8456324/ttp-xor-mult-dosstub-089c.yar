rule TTP_XOR_MULT_DOSStub_089c {
  strings:
    $key_089c = { 5c f4 [2] 28 ec [2] 6f ee [2] 28 ff [2] 66 f3 [2] 6a f9 [2] 7d f2 [2] 66 bc [2] 5b }

  condition:
    any of them
}