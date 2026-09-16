rule TTP_XOR_MULT_DOSStub_08f7 {
  strings:
    $key_08f7 = { 5c 9f [2] 28 87 [2] 6f 85 [2] 28 94 [2] 66 98 [2] 6a 92 [2] 7d 99 [2] 66 d7 [2] 5b }

  condition:
    any of them
}