rule TTP_XOR_MULT_DOSStub_2c9e {
  strings:
    $key_2c9e = { 78 f6 [2] 0c ee [2] 4b ec [2] 0c fd [2] 42 f1 [2] 4e fb [2] 59 f0 [2] 42 be [2] 7f }

  condition:
    any of them
}