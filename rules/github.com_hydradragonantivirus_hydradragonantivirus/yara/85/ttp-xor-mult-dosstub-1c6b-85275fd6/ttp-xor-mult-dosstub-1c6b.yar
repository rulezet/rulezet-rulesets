rule TTP_XOR_MULT_DOSStub_1c6b {
  strings:
    $key_1c6b = { 48 03 [2] 3c 1b [2] 7b 19 [2] 3c 08 [2] 72 04 [2] 7e 0e [2] 69 05 [2] 72 4b [2] 4f }

  condition:
    any of them
}