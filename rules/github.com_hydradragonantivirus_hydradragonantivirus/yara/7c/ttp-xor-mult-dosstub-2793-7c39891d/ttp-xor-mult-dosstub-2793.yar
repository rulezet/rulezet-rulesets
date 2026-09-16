rule TTP_XOR_MULT_DOSStub_2793 {
  strings:
    $key_2793 = { 73 fb [2] 07 e3 [2] 40 e1 [2] 07 f0 [2] 49 fc [2] 45 f6 [2] 52 fd [2] 49 b3 [2] 74 }

  condition:
    any of them
}