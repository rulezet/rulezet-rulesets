rule TTP_XOR_MULT_DOSStub_5c8d {
  strings:
    $key_5c8d = { 08 e5 [2] 7c fd [2] 3b ff [2] 7c ee [2] 32 e2 [2] 3e e8 [2] 29 e3 [2] 32 ad [2] 0f }

  condition:
    any of them
}