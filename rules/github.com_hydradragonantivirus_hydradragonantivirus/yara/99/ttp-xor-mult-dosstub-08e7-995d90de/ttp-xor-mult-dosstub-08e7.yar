rule TTP_XOR_MULT_DOSStub_08e7 {
  strings:
    $key_08e7 = { 5c 8f [2] 28 97 [2] 6f 95 [2] 28 84 [2] 66 88 [2] 6a 82 [2] 7d 89 [2] 66 c7 [2] 5b }

  condition:
    any of them
}