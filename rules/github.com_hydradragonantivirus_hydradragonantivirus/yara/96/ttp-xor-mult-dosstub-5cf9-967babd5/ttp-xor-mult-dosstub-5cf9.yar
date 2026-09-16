rule TTP_XOR_MULT_DOSStub_5cf9 {
  strings:
    $key_5cf9 = { 08 91 [2] 7c 89 [2] 3b 8b [2] 7c 9a [2] 32 96 [2] 3e 9c [2] 29 97 [2] 32 d9 [2] 0f }

  condition:
    any of them
}