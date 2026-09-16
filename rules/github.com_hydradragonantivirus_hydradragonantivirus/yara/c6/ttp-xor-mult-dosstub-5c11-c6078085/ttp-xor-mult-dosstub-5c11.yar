rule TTP_XOR_MULT_DOSStub_5c11 {
  strings:
    $key_5c11 = { 08 79 [2] 7c 61 [2] 3b 63 [2] 7c 72 [2] 32 7e [2] 3e 74 [2] 29 7f [2] 32 31 [2] 0f }

  condition:
    any of them
}