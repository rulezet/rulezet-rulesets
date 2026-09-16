rule TTP_XOR_MULT_DOSStub_5c5b {
  strings:
    $key_5c5b = { 08 33 [2] 7c 2b [2] 3b 29 [2] 7c 38 [2] 32 34 [2] 3e 3e [2] 29 35 [2] 32 7b [2] 0f }

  condition:
    any of them
}