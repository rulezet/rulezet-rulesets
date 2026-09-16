rule TTP_XOR_MULT_DOSStub_5c25 {
  strings:
    $key_5c25 = { 08 4d [2] 7c 55 [2] 3b 57 [2] 7c 46 [2] 32 4a [2] 3e 40 [2] 29 4b [2] 32 05 [2] 0f }

  condition:
    any of them
}