rule TTP_XOR_MULT_DOSStub_2d7b {
  strings:
    $key_2d7b = { 79 13 [2] 0d 0b [2] 4a 09 [2] 0d 18 [2] 43 14 [2] 4f 1e [2] 58 15 [2] 43 5b [2] 7e }

  condition:
    any of them
}