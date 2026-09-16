rule TTP_XOR_MULT_DOSStub_4de7 {
  strings:
    $key_4de7 = { 19 8f [2] 6d 97 [2] 2a 95 [2] 6d 84 [2] 23 88 [2] 2f 82 [2] 38 89 [2] 23 c7 [2] 1e }

  condition:
    any of them
}