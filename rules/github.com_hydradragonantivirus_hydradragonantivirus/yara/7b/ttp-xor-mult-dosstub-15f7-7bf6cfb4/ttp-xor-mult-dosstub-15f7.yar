rule TTP_XOR_MULT_DOSStub_15f7 {
  strings:
    $key_15f7 = { 41 9f [2] 35 87 [2] 72 85 [2] 35 94 [2] 7b 98 [2] 77 92 [2] 60 99 [2] 7b d7 [2] 46 }

  condition:
    any of them
}