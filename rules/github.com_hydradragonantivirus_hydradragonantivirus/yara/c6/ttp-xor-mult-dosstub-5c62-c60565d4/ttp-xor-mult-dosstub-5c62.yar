rule TTP_XOR_MULT_DOSStub_5c62 {
  strings:
    $key_5c62 = { 08 0a [2] 7c 12 [2] 3b 10 [2] 7c 01 [2] 32 0d [2] 3e 07 [2] 29 0c [2] 32 42 [2] 0f }

  condition:
    any of them
}