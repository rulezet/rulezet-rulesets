rule TTP_XOR_MULT_DOSStub_6634 {
  strings:
    $key_6634 = { 32 5c [2] 46 44 [2] 01 46 [2] 46 57 [2] 08 5b [2] 04 51 [2] 13 5a [2] 08 14 [2] 35 }

  condition:
    any of them
}