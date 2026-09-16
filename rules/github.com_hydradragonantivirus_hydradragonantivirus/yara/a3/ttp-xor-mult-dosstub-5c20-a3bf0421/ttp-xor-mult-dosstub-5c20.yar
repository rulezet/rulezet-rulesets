rule TTP_XOR_MULT_DOSStub_5c20 {
  strings:
    $key_5c20 = { 08 48 [2] 7c 50 [2] 3b 52 [2] 7c 43 [2] 32 4f [2] 3e 45 [2] 29 4e [2] 32 00 [2] 0f }

  condition:
    any of them
}