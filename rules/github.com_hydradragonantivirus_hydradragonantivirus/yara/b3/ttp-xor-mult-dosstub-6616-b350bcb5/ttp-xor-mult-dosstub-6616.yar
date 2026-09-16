rule TTP_XOR_MULT_DOSStub_6616 {
  strings:
    $key_6616 = { 32 7e [2] 46 66 [2] 01 64 [2] 46 75 [2] 08 79 [2] 04 73 [2] 13 78 [2] 08 36 [2] 35 }

  condition:
    any of them
}