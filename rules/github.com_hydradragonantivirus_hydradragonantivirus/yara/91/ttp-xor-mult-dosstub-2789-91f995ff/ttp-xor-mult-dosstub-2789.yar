rule TTP_XOR_MULT_DOSStub_2789 {
  strings:
    $key_2789 = { 73 e1 [2] 07 f9 [2] 40 fb [2] 07 ea [2] 49 e6 [2] 45 ec [2] 52 e7 [2] 49 a9 [2] 74 }

  condition:
    any of them
}