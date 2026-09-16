rule TTP_XOR_MULT_DOSStub_5cf0 {
  strings:
    $key_5cf0 = { 08 98 [2] 7c 80 [2] 3b 82 [2] 7c 93 [2] 32 9f [2] 3e 95 [2] 29 9e [2] 32 d0 [2] 0f }

  condition:
    any of them
}