rule TTP_XOR_MULT_DOSStub_5c6e {
  strings:
    $key_5c6e = { 08 06 [2] 7c 1e [2] 3b 1c [2] 7c 0d [2] 32 01 [2] 3e 0b [2] 29 00 [2] 32 4e [2] 0f }

  condition:
    any of them
}