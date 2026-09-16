rule TTP_XOR_MULT_DOSStub_5c48 {
  strings:
    $key_5c48 = { 08 20 [2] 7c 38 [2] 3b 3a [2] 7c 2b [2] 32 27 [2] 3e 2d [2] 29 26 [2] 32 68 [2] 0f }

  condition:
    any of them
}