rule TTP_XOR_MULT_DOSStub_5c29 {
  strings:
    $key_5c29 = { 08 41 [2] 7c 59 [2] 3b 5b [2] 7c 4a [2] 32 46 [2] 3e 4c [2] 29 47 [2] 32 09 [2] 0f }

  condition:
    any of them
}