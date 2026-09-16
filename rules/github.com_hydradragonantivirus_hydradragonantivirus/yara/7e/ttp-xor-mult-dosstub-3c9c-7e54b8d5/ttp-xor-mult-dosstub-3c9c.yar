rule TTP_XOR_MULT_DOSStub_3c9c {
  strings:
    $key_3c9c = { 68 f4 [2] 1c ec [2] 5b ee [2] 1c ff [2] 52 f3 [2] 5e f9 [2] 49 f2 [2] 52 bc [2] 6f }

  condition:
    any of them
}