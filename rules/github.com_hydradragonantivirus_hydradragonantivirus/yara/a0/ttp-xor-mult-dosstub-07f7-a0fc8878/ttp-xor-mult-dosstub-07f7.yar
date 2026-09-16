rule TTP_XOR_MULT_DOSStub_07f7 {
  strings:
    $key_07f7 = { 53 9f [2] 27 87 [2] 60 85 [2] 27 94 [2] 69 98 [2] 65 92 [2] 72 99 [2] 69 d7 [2] 54 }

  condition:
    any of them
}