rule TTP_XOR_MULT_DOSStub_6698 {
  strings:
    $key_6698 = { 32 f0 [2] 46 e8 [2] 01 ea [2] 46 fb [2] 08 f7 [2] 04 fd [2] 13 f6 [2] 08 b8 [2] 35 }

  condition:
    any of them
}