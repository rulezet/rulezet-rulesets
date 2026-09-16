rule TTP_XOR_MULT_DOSStub_789c {
  strings:
    $key_789c = { 2c f4 [2] 58 ec [2] 1f ee [2] 58 ff [2] 16 f3 [2] 1a f9 [2] 0d f2 [2] 16 bc [2] 2b }

  condition:
    any of them
}