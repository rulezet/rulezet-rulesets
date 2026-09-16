rule TTP_XOR_MULT_DOSStub_11f7 {
  strings:
    $key_11f7 = { 45 9f [2] 31 87 [2] 76 85 [2] 31 94 [2] 7f 98 [2] 73 92 [2] 64 99 [2] 7f d7 [2] 42 }

  condition:
    any of them
}