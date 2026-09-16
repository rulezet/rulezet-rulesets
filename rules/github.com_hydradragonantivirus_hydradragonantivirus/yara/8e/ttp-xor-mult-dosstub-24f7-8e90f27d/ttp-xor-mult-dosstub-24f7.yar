rule TTP_XOR_MULT_DOSStub_24f7 {
  strings:
    $key_24f7 = { 70 9f [2] 04 87 [2] 43 85 [2] 04 94 [2] 4a 98 [2] 46 92 [2] 51 99 [2] 4a d7 [2] 77 }

  condition:
    any of them
}