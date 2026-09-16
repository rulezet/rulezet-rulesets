rule TTP_XOR_MULT_DOSStub_719e {
  strings:
    $key_719e = { 25 f6 [2] 51 ee [2] 16 ec [2] 51 fd [2] 1f f1 [2] 13 fb [2] 04 f0 [2] 1f be [2] 22 }

  condition:
    any of them
}