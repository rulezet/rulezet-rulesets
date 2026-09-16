rule TTP_XOR_MULT_DOSStub_1502 {
  strings:
    $key_1502 = { 41 6a [2] 35 72 [2] 72 70 [2] 35 61 [2] 7b 6d [2] 77 67 [2] 60 6c [2] 7b 22 [2] 46 }

  condition:
    any of them
}