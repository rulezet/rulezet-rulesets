rule TTP_XOR_MULT_DOSStub_5c64 {
  strings:
    $key_5c64 = { 08 0c [2] 7c 14 [2] 3b 16 [2] 7c 07 [2] 32 0b [2] 3e 01 [2] 29 0a [2] 32 44 [2] 0f }

  condition:
    any of them
}