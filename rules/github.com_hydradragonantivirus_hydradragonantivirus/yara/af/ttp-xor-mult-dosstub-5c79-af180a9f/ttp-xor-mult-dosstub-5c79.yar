rule TTP_XOR_MULT_DOSStub_5c79 {
  strings:
    $key_5c79 = { 08 11 [2] 7c 09 [2] 3b 0b [2] 7c 1a [2] 32 16 [2] 3e 1c [2] 29 17 [2] 32 59 [2] 0f }

  condition:
    any of them
}