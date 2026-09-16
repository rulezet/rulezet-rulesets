rule TTP_XOR_MULT_DOSStub_1ee7 {
  strings:
    $key_1ee7 = { 4a 8f [2] 3e 97 [2] 79 95 [2] 3e 84 [2] 70 88 [2] 7c 82 [2] 6b 89 [2] 70 c7 [2] 4d }

  condition:
    any of them
}