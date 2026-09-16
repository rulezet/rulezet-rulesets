rule TTP_XOR_MULT_DOSStub_5c6b {
  strings:
    $key_5c6b = { 08 03 [2] 7c 1b [2] 3b 19 [2] 7c 08 [2] 32 04 [2] 3e 0e [2] 29 05 [2] 32 4b [2] 0f }

  condition:
    any of them
}