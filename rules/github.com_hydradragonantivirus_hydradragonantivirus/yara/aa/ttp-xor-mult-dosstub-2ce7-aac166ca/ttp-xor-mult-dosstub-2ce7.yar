rule TTP_XOR_MULT_DOSStub_2ce7 {
  strings:
    $key_2ce7 = { 78 8f [2] 0c 97 [2] 4b 95 [2] 0c 84 [2] 42 88 [2] 4e 82 [2] 59 89 [2] 42 c7 [2] 7f }

  condition:
    any of them
}