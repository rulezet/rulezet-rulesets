rule TTP_XOR_MULT_DOSStub_5c37 {
  strings:
    $key_5c37 = { 08 5f [2] 7c 47 [2] 3b 45 [2] 7c 54 [2] 32 58 [2] 3e 52 [2] 29 59 [2] 32 17 [2] 0f }

  condition:
    any of them
}