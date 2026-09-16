rule TTP_XOR_MULT_DOSStub_1c3b {
  strings:
    $key_1c3b = { 48 53 [2] 3c 4b [2] 7b 49 [2] 3c 58 [2] 72 54 [2] 7e 5e [2] 69 55 [2] 72 1b [2] 4f }

  condition:
    any of them
}