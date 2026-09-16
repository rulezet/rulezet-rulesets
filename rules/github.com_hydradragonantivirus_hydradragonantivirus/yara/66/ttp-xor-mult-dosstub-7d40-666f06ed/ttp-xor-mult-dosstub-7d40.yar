rule TTP_XOR_MULT_DOSStub_7d40 {
  strings:
    $key_7d40 = { 29 28 [2] 5d 30 [2] 1a 32 [2] 5d 23 [2] 13 2f [2] 1f 25 [2] 08 2e [2] 13 60 [2] 2e }

  condition:
    any of them
}