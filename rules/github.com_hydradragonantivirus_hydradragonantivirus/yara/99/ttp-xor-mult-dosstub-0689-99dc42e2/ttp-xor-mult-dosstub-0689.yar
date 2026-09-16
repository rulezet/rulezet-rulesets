rule TTP_XOR_MULT_DOSStub_0689 {
  strings:
    $key_0689 = { 52 e1 [2] 26 f9 [2] 61 fb [2] 26 ea [2] 68 e6 [2] 64 ec [2] 73 e7 [2] 68 a9 [2] 55 }

  condition:
    any of them
}