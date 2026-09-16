rule TTP_XOR_MULT_DOSStub_2093 {
  strings:
    $key_2093 = { 74 fb [2] 00 e3 [2] 47 e1 [2] 00 f0 [2] 4e fc [2] 42 f6 [2] 55 fd [2] 4e b3 [2] 73 }

  condition:
    any of them
}