rule TTP_XOR_MULT_DOSStub_1523 {
  strings:
    $key_1523 = { 41 4b [2] 35 53 [2] 72 51 [2] 35 40 [2] 7b 4c [2] 77 46 [2] 60 4d [2] 7b 03 [2] 46 }

  condition:
    any of them
}