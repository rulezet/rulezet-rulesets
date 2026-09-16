rule TTP_XOR_MULT_DOSStub_4d93 {
  strings:
    $key_4d93 = { 19 fb [2] 6d e3 [2] 2a e1 [2] 6d f0 [2] 23 fc [2] 2f f6 [2] 38 fd [2] 23 b3 [2] 1e }

  condition:
    any of them
}