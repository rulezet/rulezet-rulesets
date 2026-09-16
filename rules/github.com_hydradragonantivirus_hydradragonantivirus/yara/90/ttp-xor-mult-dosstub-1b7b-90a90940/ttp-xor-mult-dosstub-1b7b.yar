rule TTP_XOR_MULT_DOSStub_1b7b {
  strings:
    $key_1b7b = { 4f 13 [2] 3b 0b [2] 7c 09 [2] 3b 18 [2] 75 14 [2] 79 1e [2] 6e 15 [2] 75 5b [2] 48 }

  condition:
    any of them
}