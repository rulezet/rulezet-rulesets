rule TTP_XOR_MULT_DOSStub_5be7 {
  strings:
    $key_5be7 = { 0f 8f [2] 7b 97 [2] 3c 95 [2] 7b 84 [2] 35 88 [2] 39 82 [2] 2e 89 [2] 35 c7 [2] 08 }

  condition:
    any of them
}