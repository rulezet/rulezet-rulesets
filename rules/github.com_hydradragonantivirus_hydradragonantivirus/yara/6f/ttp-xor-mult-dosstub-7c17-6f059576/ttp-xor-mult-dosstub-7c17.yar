rule TTP_XOR_MULT_DOSStub_7c17 {
  strings:
    $key_7c17 = { 28 7f [2] 5c 67 [2] 1b 65 [2] 5c 74 [2] 12 78 [2] 1e 72 [2] 09 79 [2] 12 37 [2] 2f }

  condition:
    any of them
}