rule TTP_XOR_MULT_DOSStub_5c60 {
  strings:
    $key_5c60 = { 08 08 [2] 7c 10 [2] 3b 12 [2] 7c 03 [2] 32 0f [2] 3e 05 [2] 29 0e [2] 32 40 [2] 0f }

  condition:
    any of them
}