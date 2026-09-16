rule TTP_XOR_MULT_DOSStub_5ce1 {
  strings:
    $key_5ce1 = { 08 89 [2] 7c 91 [2] 3b 93 [2] 7c 82 [2] 32 8e [2] 3e 84 [2] 29 8f [2] 32 c1 [2] 0f }

  condition:
    any of them
}