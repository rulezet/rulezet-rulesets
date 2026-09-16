rule TTP_XOR_MULT_DOSStub_5b7b {
  strings:
    $key_5b7b = { 0f 13 [2] 7b 0b [2] 3c 09 [2] 7b 18 [2] 35 14 [2] 39 1e [2] 2e 15 [2] 35 5b [2] 08 }

  condition:
    any of them
}