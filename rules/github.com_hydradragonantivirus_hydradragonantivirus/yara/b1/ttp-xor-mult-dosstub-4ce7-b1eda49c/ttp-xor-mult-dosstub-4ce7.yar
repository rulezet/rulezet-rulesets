rule TTP_XOR_MULT_DOSStub_4ce7 {
  strings:
    $key_4ce7 = { 18 8f [2] 6c 97 [2] 2b 95 [2] 6c 84 [2] 22 88 [2] 2e 82 [2] 39 89 [2] 22 c7 [2] 1f }

  condition:
    any of them
}