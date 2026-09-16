rule TTP_XOR_MULT_DOSStub_1b32 {
  strings:
    $key_1b32 = { 4f 5a [2] 3b 42 [2] 7c 40 [2] 3b 51 [2] 75 5d [2] 79 57 [2] 6e 5c [2] 75 12 [2] 48 }

  condition:
    any of them
}