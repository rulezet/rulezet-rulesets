rule TTP_XOR_MULT_DOSStub_5cf7 {
  strings:
    $key_5cf7 = { 08 9f [2] 7c 87 [2] 3b 85 [2] 7c 94 [2] 32 98 [2] 3e 92 [2] 29 99 [2] 32 d7 [2] 0f }

  condition:
    any of them
}