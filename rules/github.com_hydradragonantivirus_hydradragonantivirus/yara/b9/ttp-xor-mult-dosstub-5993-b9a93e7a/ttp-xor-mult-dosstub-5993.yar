rule TTP_XOR_MULT_DOSStub_5993 {
  strings:
    $key_5993 = { 0d fb [2] 79 e3 [2] 3e e1 [2] 79 f0 [2] 37 fc [2] 3b f6 [2] 2c fd [2] 37 b3 [2] 0a }

  condition:
    any of them
}