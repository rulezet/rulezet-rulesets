rule TTP_XOR_MULT_DOSStub_0893 {
  strings:
    $key_0893 = { 5c fb [2] 28 e3 [2] 6f e1 [2] 28 f0 [2] 66 fc [2] 6a f6 [2] 7d fd [2] 66 b3 [2] 5b }

  condition:
    any of them
}