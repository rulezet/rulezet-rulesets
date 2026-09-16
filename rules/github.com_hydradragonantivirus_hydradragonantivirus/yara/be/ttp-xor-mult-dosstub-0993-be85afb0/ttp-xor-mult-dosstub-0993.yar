rule TTP_XOR_MULT_DOSStub_0993 {
  strings:
    $key_0993 = { 5d fb [2] 29 e3 [2] 6e e1 [2] 29 f0 [2] 67 fc [2] 6b f6 [2] 7c fd [2] 67 b3 [2] 5a }

  condition:
    any of them
}