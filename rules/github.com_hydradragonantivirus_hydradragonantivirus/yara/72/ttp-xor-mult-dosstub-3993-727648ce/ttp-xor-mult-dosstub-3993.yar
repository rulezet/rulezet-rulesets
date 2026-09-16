rule TTP_XOR_MULT_DOSStub_3993 {
  strings:
    $key_3993 = { 6d fb [2] 19 e3 [2] 5e e1 [2] 19 f0 [2] 57 fc [2] 5b f6 [2] 4c fd [2] 57 b3 [2] 6a }

  condition:
    any of them
}