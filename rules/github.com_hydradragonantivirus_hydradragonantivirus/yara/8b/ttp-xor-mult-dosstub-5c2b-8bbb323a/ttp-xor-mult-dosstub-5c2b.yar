rule TTP_XOR_MULT_DOSStub_5c2b {
  strings:
    $key_5c2b = { 08 43 [2] 7c 5b [2] 3b 59 [2] 7c 48 [2] 32 44 [2] 3e 4e [2] 29 45 [2] 32 0b [2] 0f }

  condition:
    any of them
}