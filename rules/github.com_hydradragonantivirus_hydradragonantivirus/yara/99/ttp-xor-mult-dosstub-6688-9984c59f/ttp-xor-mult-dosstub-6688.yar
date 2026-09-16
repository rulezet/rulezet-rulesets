rule TTP_XOR_MULT_DOSStub_6688 {
  strings:
    $key_6688 = { 32 e0 [2] 46 f8 [2] 01 fa [2] 46 eb [2] 08 e7 [2] 04 ed [2] 13 e6 [2] 08 a8 [2] 35 }

  condition:
    any of them
}