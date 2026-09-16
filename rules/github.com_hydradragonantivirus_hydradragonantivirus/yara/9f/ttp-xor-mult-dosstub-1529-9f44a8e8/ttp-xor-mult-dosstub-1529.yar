rule TTP_XOR_MULT_DOSStub_1529 {
  strings:
    $key_1529 = { 41 41 [2] 35 59 [2] 72 5b [2] 35 4a [2] 7b 46 [2] 77 4c [2] 60 47 [2] 7b 09 [2] 46 }

  condition:
    any of them
}