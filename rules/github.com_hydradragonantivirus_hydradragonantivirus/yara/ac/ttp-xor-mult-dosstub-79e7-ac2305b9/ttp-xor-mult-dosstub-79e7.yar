rule TTP_XOR_MULT_DOSStub_79e7 {
  strings:
    $key_79e7 = { 2d 8f [2] 59 97 [2] 1e 95 [2] 59 84 [2] 17 88 [2] 1b 82 [2] 0c 89 [2] 17 c7 [2] 2a }

  condition:
    any of them
}