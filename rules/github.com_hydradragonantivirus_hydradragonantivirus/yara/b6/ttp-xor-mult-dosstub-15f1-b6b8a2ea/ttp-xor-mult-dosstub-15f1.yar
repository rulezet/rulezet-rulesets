rule TTP_XOR_MULT_DOSStub_15f1 {
  strings:
    $key_15f1 = { 41 99 [2] 35 81 [2] 72 83 [2] 35 92 [2] 7b 9e [2] 77 94 [2] 60 9f [2] 7b d1 [2] 46 }

  condition:
    any of them
}