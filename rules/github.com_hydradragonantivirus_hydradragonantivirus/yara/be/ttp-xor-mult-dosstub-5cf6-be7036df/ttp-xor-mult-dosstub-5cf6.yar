rule TTP_XOR_MULT_DOSStub_5cf6 {
  strings:
    $key_5cf6 = { 08 9e [2] 7c 86 [2] 3b 84 [2] 7c 95 [2] 32 99 [2] 3e 93 [2] 29 98 [2] 32 d6 [2] 0f }

  condition:
    any of them
}