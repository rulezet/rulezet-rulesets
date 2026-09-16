rule TTP_XOR_MULT_DOSStub_1534 {
  strings:
    $key_1534 = { 41 5c [2] 35 44 [2] 72 46 [2] 35 57 [2] 7b 5b [2] 77 51 [2] 60 5a [2] 7b 14 [2] 46 }

  condition:
    any of them
}