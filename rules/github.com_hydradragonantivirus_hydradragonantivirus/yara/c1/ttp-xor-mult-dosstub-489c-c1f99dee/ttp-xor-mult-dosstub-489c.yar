rule TTP_XOR_MULT_DOSStub_489c {
  strings:
    $key_489c = { 1c f4 [2] 68 ec [2] 2f ee [2] 68 ff [2] 26 f3 [2] 2a f9 [2] 3d f2 [2] 26 bc [2] 1b }

  condition:
    any of them
}