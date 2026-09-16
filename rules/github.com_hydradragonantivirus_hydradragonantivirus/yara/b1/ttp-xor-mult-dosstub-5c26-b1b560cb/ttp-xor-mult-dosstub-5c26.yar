rule TTP_XOR_MULT_DOSStub_5c26 {
  strings:
    $key_5c26 = { 08 4e [2] 7c 56 [2] 3b 54 [2] 7c 45 [2] 32 49 [2] 3e 43 [2] 29 48 [2] 32 06 [2] 0f }

  condition:
    any of them
}