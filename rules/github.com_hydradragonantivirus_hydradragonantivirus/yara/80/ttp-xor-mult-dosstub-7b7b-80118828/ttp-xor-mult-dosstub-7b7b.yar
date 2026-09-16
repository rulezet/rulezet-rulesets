rule TTP_XOR_MULT_DOSStub_7b7b {
  strings:
    $key_7b7b = { 2f 13 [2] 5b 0b [2] 1c 09 [2] 5b 18 [2] 15 14 [2] 19 1e [2] 0e 15 [2] 15 5b [2] 28 }

  condition:
    any of them
}