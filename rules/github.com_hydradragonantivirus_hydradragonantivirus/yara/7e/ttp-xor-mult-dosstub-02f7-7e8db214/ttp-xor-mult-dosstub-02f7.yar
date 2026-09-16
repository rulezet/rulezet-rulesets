rule TTP_XOR_MULT_DOSStub_02f7 {
  strings:
    $key_02f7 = { 56 9f [2] 22 87 [2] 65 85 [2] 22 94 [2] 6c 98 [2] 60 92 [2] 77 99 [2] 6c d7 [2] 51 }

  condition:
    any of them
}