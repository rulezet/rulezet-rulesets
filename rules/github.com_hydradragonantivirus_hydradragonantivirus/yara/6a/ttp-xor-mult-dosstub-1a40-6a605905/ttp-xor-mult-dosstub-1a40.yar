rule TTP_XOR_MULT_DOSStub_1a40 {
  strings:
    $key_1a40 = { 4e 28 [2] 3a 30 [2] 7d 32 [2] 3a 23 [2] 74 2f [2] 78 25 [2] 6f 2e [2] 74 60 [2] 49 }

  condition:
    any of them
}