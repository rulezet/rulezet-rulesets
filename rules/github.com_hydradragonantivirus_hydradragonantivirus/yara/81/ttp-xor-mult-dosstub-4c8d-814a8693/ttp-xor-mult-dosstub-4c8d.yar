rule TTP_XOR_MULT_DOSStub_4c8d {
  strings:
    $key_4c8d = { 18 e5 [2] 6c fd [2] 2b ff [2] 6c ee [2] 22 e2 [2] 2e e8 [2] 39 e3 [2] 22 ad [2] 1f }

  condition:
    any of them
}