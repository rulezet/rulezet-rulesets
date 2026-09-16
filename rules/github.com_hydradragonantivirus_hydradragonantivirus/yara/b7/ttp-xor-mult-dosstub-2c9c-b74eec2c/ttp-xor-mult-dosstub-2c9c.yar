rule TTP_XOR_MULT_DOSStub_2c9c {
  strings:
    $key_2c9c = { 78 f4 [2] 0c ec [2] 4b ee [2] 0c ff [2] 42 f3 [2] 4e f9 [2] 59 f2 [2] 42 bc [2] 7f }

  condition:
    any of them
}