rule TTP_XOR_MULT_DOSStub_729e {
  strings:
    $key_729e = { 26 f6 [2] 52 ee [2] 15 ec [2] 52 fd [2] 1c f1 [2] 10 fb [2] 07 f0 [2] 1c be [2] 21 }

  condition:
    any of them
}