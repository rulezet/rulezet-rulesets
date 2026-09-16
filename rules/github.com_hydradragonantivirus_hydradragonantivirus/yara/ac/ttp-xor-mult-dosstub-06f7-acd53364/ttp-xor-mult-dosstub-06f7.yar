rule TTP_XOR_MULT_DOSStub_06f7 {
  strings:
    $key_06f7 = { 52 9f [2] 26 87 [2] 61 85 [2] 26 94 [2] 68 98 [2] 64 92 [2] 73 99 [2] 68 d7 [2] 55 }

  condition:
    any of them
}