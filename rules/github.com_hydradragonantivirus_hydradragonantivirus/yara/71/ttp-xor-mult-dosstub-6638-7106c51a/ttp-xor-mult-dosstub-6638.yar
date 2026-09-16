rule TTP_XOR_MULT_DOSStub_6638 {
  strings:
    $key_6638 = { 32 50 [2] 46 48 [2] 01 4a [2] 46 5b [2] 08 57 [2] 04 5d [2] 13 56 [2] 08 18 [2] 35 }

  condition:
    any of them
}