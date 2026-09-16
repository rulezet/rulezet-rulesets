rule TTP_XOR_MULT_DOSStub_25f7 {
  strings:
    $key_25f7 = { 71 9f [2] 05 87 [2] 42 85 [2] 05 94 [2] 4b 98 [2] 47 92 [2] 50 99 [2] 4b d7 [2] 76 }

  condition:
    any of them
}