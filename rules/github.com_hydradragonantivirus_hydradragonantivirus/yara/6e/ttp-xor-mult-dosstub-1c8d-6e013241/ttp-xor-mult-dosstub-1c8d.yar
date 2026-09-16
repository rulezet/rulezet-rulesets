rule TTP_XOR_MULT_DOSStub_1c8d {
  strings:
    $key_1c8d = { 48 e5 [2] 3c fd [2] 7b ff [2] 3c ee [2] 72 e2 [2] 7e e8 [2] 69 e3 [2] 72 ad [2] 4f }

  condition:
    any of them
}