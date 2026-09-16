rule TTP_XOR_MULT_DOSStub_0b7b {
  strings:
    $key_0b7b = { 5f 13 [2] 2b 0b [2] 6c 09 [2] 2b 18 [2] 65 14 [2] 69 1e [2] 7e 15 [2] 65 5b [2] 58 }

  condition:
    any of them
}