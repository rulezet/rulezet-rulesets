rule TTP_XOR_MULT_DOSStub_1518 {
  strings:
    $key_1518 = { 41 70 [2] 35 68 [2] 72 6a [2] 35 7b [2] 7b 77 [2] 77 7d [2] 60 76 [2] 7b 38 [2] 46 }

  condition:
    any of them
}