rule TTP_XOR_MULT_DOSStub_589c {
  strings:
    $key_589c = { 0c f4 [2] 78 ec [2] 3f ee [2] 78 ff [2] 36 f3 [2] 3a f9 [2] 2d f2 [2] 36 bc [2] 0b }

  condition:
    any of them
}