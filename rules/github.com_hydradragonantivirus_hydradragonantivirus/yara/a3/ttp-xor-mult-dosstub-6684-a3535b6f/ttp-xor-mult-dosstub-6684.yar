rule TTP_XOR_MULT_DOSStub_6684 {
  strings:
    $key_6684 = { 32 ec [2] 46 f4 [2] 01 f6 [2] 46 e7 [2] 08 eb [2] 04 e1 [2] 13 ea [2] 08 a4 [2] 35 }

  condition:
    any of them
}