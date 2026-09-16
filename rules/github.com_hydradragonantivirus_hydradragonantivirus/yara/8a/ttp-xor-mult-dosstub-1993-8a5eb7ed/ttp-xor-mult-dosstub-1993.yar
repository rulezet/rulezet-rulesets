rule TTP_XOR_MULT_DOSStub_1993 {
  strings:
    $key_1993 = { 4d fb [2] 39 e3 [2] 7e e1 [2] 39 f0 [2] 77 fc [2] 7b f6 [2] 6c fd [2] 77 b3 [2] 4a }

  condition:
    any of them
}