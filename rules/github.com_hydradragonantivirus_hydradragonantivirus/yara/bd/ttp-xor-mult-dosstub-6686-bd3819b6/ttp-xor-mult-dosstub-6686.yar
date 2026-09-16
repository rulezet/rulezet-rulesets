rule TTP_XOR_MULT_DOSStub_6686 {
  strings:
    $key_6686 = { 32 ee [2] 46 f6 [2] 01 f4 [2] 46 e5 [2] 08 e9 [2] 04 e3 [2] 13 e8 [2] 08 a6 [2] 35 }

  condition:
    any of them
}