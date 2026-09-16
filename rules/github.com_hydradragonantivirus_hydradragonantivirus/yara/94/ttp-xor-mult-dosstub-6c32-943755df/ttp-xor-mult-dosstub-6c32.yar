rule TTP_XOR_MULT_DOSStub_6c32 {
  strings:
    $key_6c32 = { 38 5a [2] 4c 42 [2] 0b 40 [2] 4c 51 [2] 02 5d [2] 0e 57 [2] 19 5c [2] 02 12 [2] 3f }

  condition:
    any of them
}