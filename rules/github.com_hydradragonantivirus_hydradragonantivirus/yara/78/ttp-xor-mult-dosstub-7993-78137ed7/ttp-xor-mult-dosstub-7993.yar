rule TTP_XOR_MULT_DOSStub_7993 {
  strings:
    $key_7993 = { 2d fb [2] 59 e3 [2] 1e e1 [2] 59 f0 [2] 17 fc [2] 1b f6 [2] 0c fd [2] 17 b3 [2] 2a }

  condition:
    any of them
}