rule TTP_XOR_MULT_DOSStub_04f7 {
  strings:
    $key_04f7 = { 50 9f [2] 24 87 [2] 63 85 [2] 24 94 [2] 6a 98 [2] 66 92 [2] 71 99 [2] 6a d7 [2] 57 }

  condition:
    any of them
}