rule TTP_XOR_MULT_DOSStub_5c73 {
  strings:
    $key_5c73 = { 08 1b [2] 7c 03 [2] 3b 01 [2] 7c 10 [2] 32 1c [2] 3e 16 [2] 29 1d [2] 32 53 [2] 0f }

  condition:
    any of them
}