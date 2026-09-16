rule TTP_XOR_MULT_DOSStub_5c75 {
  strings:
    $key_5c75 = { 08 1d [2] 7c 05 [2] 3b 07 [2] 7c 16 [2] 32 1a [2] 3e 10 [2] 29 1b [2] 32 55 [2] 0f }

  condition:
    any of them
}