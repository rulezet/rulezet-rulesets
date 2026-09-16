rule TTP_XOR_MULT_DOSStub_0af7 {
  strings:
    $key_0af7 = { 5e 9f [2] 2a 87 [2] 6d 85 [2] 2a 94 [2] 64 98 [2] 68 92 [2] 7f 99 [2] 64 d7 [2] 59 }

  condition:
    any of them
}