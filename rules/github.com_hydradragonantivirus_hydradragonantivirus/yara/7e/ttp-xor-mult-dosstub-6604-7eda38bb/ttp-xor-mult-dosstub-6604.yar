rule TTP_XOR_MULT_DOSStub_6604 {
  strings:
    $key_6604 = { 32 6c [2] 46 74 [2] 01 76 [2] 46 67 [2] 08 6b [2] 04 61 [2] 13 6a [2] 08 24 [2] 35 }

  condition:
    any of them
}