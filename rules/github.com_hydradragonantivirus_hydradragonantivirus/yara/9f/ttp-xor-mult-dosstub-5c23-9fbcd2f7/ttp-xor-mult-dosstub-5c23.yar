rule TTP_XOR_MULT_DOSStub_5c23 {
  strings:
    $key_5c23 = { 08 4b [2] 7c 53 [2] 3b 51 [2] 7c 40 [2] 32 4c [2] 3e 46 [2] 29 4d [2] 32 03 [2] 0f }

  condition:
    any of them
}