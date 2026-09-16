rule TTP_XOR_MULT_DOSStub_5de7 {
  strings:
    $key_5de7 = { 09 8f [2] 7d 97 [2] 3a 95 [2] 7d 84 [2] 33 88 [2] 3f 82 [2] 28 89 [2] 33 c7 [2] 0e }

  condition:
    any of them
}