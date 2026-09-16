rule TTP_XOR_MULT_DOSStub_5c9c {
  strings:
    $key_5c9c = { 08 f4 [2] 7c ec [2] 3b ee [2] 7c ff [2] 32 f3 [2] 3e f9 [2] 29 f2 [2] 32 bc [2] 0f }

  condition:
    any of them
}