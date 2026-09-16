rule TTP_XOR_MULT_DOSStub_5cf4 {
  strings:
    $key_5cf4 = { 08 9c [2] 7c 84 [2] 3b 86 [2] 7c 97 [2] 32 9b [2] 3e 91 [2] 29 9a [2] 32 d4 [2] 0f }

  condition:
    any of them
}