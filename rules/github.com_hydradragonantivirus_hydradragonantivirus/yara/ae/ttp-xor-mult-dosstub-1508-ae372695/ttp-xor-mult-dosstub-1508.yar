rule TTP_XOR_MULT_DOSStub_1508 {
  strings:
    $key_1508 = { 41 60 [2] 35 78 [2] 72 7a [2] 35 6b [2] 7b 67 [2] 77 6d [2] 60 66 [2] 7b 28 [2] 46 }

  condition:
    any of them
}