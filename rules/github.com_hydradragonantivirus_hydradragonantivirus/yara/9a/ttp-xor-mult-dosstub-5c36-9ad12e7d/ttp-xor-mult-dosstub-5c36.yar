rule TTP_XOR_MULT_DOSStub_5c36 {
  strings:
    $key_5c36 = { 08 5e [2] 7c 46 [2] 3b 44 [2] 7c 55 [2] 32 59 [2] 3e 53 [2] 29 58 [2] 32 16 [2] 0f }

  condition:
    any of them
}