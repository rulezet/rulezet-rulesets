rule TTP_XOR_MULT_DOSStub_1524 {
  strings:
    $key_1524 = { 41 4c [2] 35 54 [2] 72 56 [2] 35 47 [2] 7b 4b [2] 77 41 [2] 60 4a [2] 7b 04 [2] 46 }

  condition:
    any of them
}