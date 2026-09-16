rule TTP_XOR_MULT_DOSStub_6697 {
  strings:
    $key_6697 = { 32 ff [2] 46 e7 [2] 01 e5 [2] 46 f4 [2] 08 f8 [2] 04 f2 [2] 13 f9 [2] 08 b7 [2] 35 }

  condition:
    any of them
}