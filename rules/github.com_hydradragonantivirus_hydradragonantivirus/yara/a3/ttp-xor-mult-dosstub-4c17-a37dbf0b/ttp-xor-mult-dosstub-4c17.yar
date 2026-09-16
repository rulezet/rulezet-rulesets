rule TTP_XOR_MULT_DOSStub_4c17 {
  strings:
    $key_4c17 = { 18 7f [2] 6c 67 [2] 2b 65 [2] 6c 74 [2] 22 78 [2] 2e 72 [2] 39 79 [2] 22 37 [2] 1f }

  condition:
    any of them
}