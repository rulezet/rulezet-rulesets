rule TTP_XOR_MULT_DOSStub_5d40 {
  strings:
    $key_5d40 = { 09 28 [2] 7d 30 [2] 3a 32 [2] 7d 23 [2] 33 2f [2] 3f 25 [2] 28 2e [2] 33 60 [2] 0e }

  condition:
    any of them
}