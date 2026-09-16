rule TTP_XOR_MULT_DOSStub_0ff7 {
  strings:
    $key_0ff7 = { 5b 9f [2] 2f 87 [2] 68 85 [2] 2f 94 [2] 61 98 [2] 6d 92 [2] 7a 99 [2] 61 d7 [2] 5c }

  condition:
    any of them
}