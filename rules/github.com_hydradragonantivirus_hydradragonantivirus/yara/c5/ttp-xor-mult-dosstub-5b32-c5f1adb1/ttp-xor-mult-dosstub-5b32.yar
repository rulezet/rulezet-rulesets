rule TTP_XOR_MULT_DOSStub_5b32 {
  strings:
    $key_5b32 = { 0f 5a [2] 7b 42 [2] 3c 40 [2] 7b 51 [2] 35 5d [2] 39 57 [2] 2e 5c [2] 35 12 [2] 08 }

  condition:
    any of them
}