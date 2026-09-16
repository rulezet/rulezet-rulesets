rule TTP_XOR_MULT_DOSStub_7ae7 {
  strings:
    $key_7ae7 = { 2e 8f [2] 5a 97 [2] 1d 95 [2] 5a 84 [2] 14 88 [2] 18 82 [2] 0f 89 [2] 14 c7 [2] 29 }

  condition:
    any of them
}