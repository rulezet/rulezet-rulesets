rule TTP_XOR_MULT_DOSStub_1c1b {
  strings:
    $key_1c1b = { 48 73 [2] 3c 6b [2] 7b 69 [2] 3c 78 [2] 72 74 [2] 7e 7e [2] 69 75 [2] 72 3b [2] 4f }

  condition:
    any of them
}