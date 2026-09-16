rule TTP_XOR_MULT_DOSStub_49f7 {
  strings:
    $key_49f7 = { 1d 9f [2] 69 87 [2] 2e 85 [2] 69 94 [2] 27 98 [2] 2b 92 [2] 3c 99 [2] 27 d7 [2] 1a }

  condition:
    any of them
}