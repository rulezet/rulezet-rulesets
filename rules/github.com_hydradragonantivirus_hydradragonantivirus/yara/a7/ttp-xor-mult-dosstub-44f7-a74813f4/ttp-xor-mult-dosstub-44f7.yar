rule TTP_XOR_MULT_DOSStub_44f7 {
  strings:
    $key_44f7 = { 10 9f [2] 64 87 [2] 23 85 [2] 64 94 [2] 2a 98 [2] 26 92 [2] 31 99 [2] 2a d7 [2] 17 }

  condition:
    any of them
}