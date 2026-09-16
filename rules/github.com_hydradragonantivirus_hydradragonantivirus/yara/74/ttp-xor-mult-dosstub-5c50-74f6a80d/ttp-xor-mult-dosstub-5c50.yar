rule TTP_XOR_MULT_DOSStub_5c50 {
  strings:
    $key_5c50 = { 08 38 [2] 7c 20 [2] 3b 22 [2] 7c 33 [2] 32 3f [2] 3e 35 [2] 29 3e [2] 32 70 [2] 0f }

  condition:
    any of them
}