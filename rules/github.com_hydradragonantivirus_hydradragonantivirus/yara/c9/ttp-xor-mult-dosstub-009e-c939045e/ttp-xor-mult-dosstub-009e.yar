rule TTP_XOR_MULT_DOSStub_009e {
  strings:
    $key_009e = { 54 f6 [2] 20 ee [2] 67 ec [2] 20 fd [2] 6e f1 [2] 62 fb [2] 75 f0 [2] 6e be [2] 53 }

  condition:
    any of them
}