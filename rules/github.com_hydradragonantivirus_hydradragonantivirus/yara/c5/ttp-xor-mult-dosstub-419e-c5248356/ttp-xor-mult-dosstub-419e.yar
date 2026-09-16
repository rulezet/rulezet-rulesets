rule TTP_XOR_MULT_DOSStub_419e {
  strings:
    $key_419e = { 15 f6 [2] 61 ee [2] 26 ec [2] 61 fd [2] 2f f1 [2] 23 fb [2] 34 f0 [2] 2f be [2] 12 }

  condition:
    any of them
}