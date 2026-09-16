rule TTP_XOR_MULT_DOSStub_5c30 {
  strings:
    $key_5c30 = { 08 58 [2] 7c 40 [2] 3b 42 [2] 7c 53 [2] 32 5f [2] 3e 55 [2] 29 5e [2] 32 10 [2] 0f }

  condition:
    any of them
}