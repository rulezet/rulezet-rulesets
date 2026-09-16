rule TTP_XOR_MULT_DOSStub_1564 {
  strings:
    $key_1564 = { 41 0c [2] 35 14 [2] 72 16 [2] 35 07 [2] 7b 0b [2] 77 01 [2] 60 0a [2] 7b 44 [2] 46 }

  condition:
    any of them
}