rule TTP_XOR_MULT_DOSStub_6993 {
  strings:
    $key_6993 = { 3d fb [2] 49 e3 [2] 0e e1 [2] 49 f0 [2] 07 fc [2] 0b f6 [2] 1c fd [2] 07 b3 [2] 3a }

  condition:
    any of them
}