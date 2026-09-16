rule TTP_XOR_MULT_DOSStub_1c9c {
  strings:
    $key_1c9c = { 48 f4 [2] 3c ec [2] 7b ee [2] 3c ff [2] 72 f3 [2] 7e f9 [2] 69 f2 [2] 72 bc [2] 4f }

  condition:
    any of them
}