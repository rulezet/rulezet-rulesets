rule TTP_XOR_MULT_DOSStub_6c7b {
  strings:
    $key_6c7b = { 38 13 [2] 4c 0b [2] 0b 09 [2] 4c 18 [2] 02 14 [2] 0e 1e [2] 19 15 [2] 02 5b [2] 3f }

  condition:
    any of them
}