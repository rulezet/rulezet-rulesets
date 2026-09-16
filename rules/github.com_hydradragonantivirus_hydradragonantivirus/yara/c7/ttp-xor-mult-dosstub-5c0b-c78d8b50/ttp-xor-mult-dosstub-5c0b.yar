rule TTP_XOR_MULT_DOSStub_5c0b {
  strings:
    $key_5c0b = { 08 63 [2] 7c 7b [2] 3b 79 [2] 7c 68 [2] 32 64 [2] 3e 6e [2] 29 65 [2] 32 2b [2] 0f }

  condition:
    any of them
}