rule TTP_XOR_MULT_DOSStub_6611 {
  strings:
    $key_6611 = { 32 79 [2] 46 61 [2] 01 63 [2] 46 72 [2] 08 7e [2] 04 74 [2] 13 7f [2] 08 31 [2] 35 }

  condition:
    any of them
}