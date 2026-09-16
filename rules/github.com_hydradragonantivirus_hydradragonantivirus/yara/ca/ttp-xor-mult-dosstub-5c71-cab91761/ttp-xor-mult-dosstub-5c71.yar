rule TTP_XOR_MULT_DOSStub_5c71 {
  strings:
    $key_5c71 = { 08 19 [2] 7c 01 [2] 3b 03 [2] 7c 12 [2] 32 1e [2] 3e 14 [2] 29 1f [2] 32 51 [2] 0f }

  condition:
    any of them
}