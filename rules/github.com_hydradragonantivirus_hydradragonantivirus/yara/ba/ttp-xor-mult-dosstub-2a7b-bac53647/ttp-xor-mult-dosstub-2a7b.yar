rule TTP_XOR_MULT_DOSStub_2a7b {
  strings:
    $key_2a7b = { 7e 13 [2] 0a 0b [2] 4d 09 [2] 0a 18 [2] 44 14 [2] 48 1e [2] 5f 15 [2] 44 5b [2] 79 }

  condition:
    any of them
}