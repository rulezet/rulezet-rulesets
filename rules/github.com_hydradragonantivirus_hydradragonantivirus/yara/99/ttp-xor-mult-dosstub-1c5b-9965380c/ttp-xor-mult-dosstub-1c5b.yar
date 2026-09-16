rule TTP_XOR_MULT_DOSStub_1c5b {
  strings:
    $key_1c5b = { 48 33 [2] 3c 2b [2] 7b 29 [2] 3c 38 [2] 72 34 [2] 7e 3e [2] 69 35 [2] 72 7b [2] 4f }

  condition:
    any of them
}