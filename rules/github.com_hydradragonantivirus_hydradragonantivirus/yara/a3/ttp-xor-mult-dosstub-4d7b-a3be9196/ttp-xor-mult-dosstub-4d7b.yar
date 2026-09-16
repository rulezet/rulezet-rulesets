rule TTP_XOR_MULT_DOSStub_4d7b {
  strings:
    $key_4d7b = { 19 13 [2] 6d 0b [2] 2a 09 [2] 6d 18 [2] 23 14 [2] 2f 1e [2] 38 15 [2] 23 5b [2] 1e }

  condition:
    any of them
}