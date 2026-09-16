rule TTP_XOR_MULT_DOSStub_39f7 {
  strings:
    $key_39f7 = { 6d 9f [2] 19 87 [2] 5e 85 [2] 19 94 [2] 57 98 [2] 5b 92 [2] 4c 99 [2] 57 d7 [2] 6a }

  condition:
    any of them
}