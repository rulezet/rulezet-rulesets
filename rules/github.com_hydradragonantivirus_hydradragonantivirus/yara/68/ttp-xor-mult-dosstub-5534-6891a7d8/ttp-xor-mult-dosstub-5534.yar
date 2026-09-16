rule TTP_XOR_MULT_DOSStub_5534 {
  strings:
    $key_5534 = { 01 5c [2] 75 44 [2] 32 46 [2] 75 57 [2] 3b 5b [2] 37 51 [2] 20 5a [2] 3b 14 [2] 06 }

  condition:
    any of them
}