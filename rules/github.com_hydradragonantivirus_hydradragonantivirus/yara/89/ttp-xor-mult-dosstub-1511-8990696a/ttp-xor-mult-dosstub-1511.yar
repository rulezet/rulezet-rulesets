rule TTP_XOR_MULT_DOSStub_1511 {
  strings:
    $key_1511 = { 41 79 [2] 35 61 [2] 72 63 [2] 35 72 [2] 7b 7e [2] 77 74 [2] 60 7f [2] 7b 31 [2] 46 }

  condition:
    any of them
}