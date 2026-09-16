rule TTP_XOR_MULT_DOSStub_6617 {
  strings:
    $key_6617 = { 32 7f [2] 46 67 [2] 01 65 [2] 46 74 [2] 08 78 [2] 04 72 [2] 13 79 [2] 08 37 [2] 35 }

  condition:
    any of them
}