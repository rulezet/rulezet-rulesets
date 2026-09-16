rule TTP_XOR_MULT_DOSStub_5c28 {
  strings:
    $key_5c28 = { 08 40 [2] 7c 58 [2] 3b 5a [2] 7c 4b [2] 32 47 [2] 3e 4d [2] 29 46 [2] 32 08 [2] 0f }

  condition:
    any of them
}