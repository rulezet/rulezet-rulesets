rule TTP_XOR_MULT_DOSStub_6c62 {
  strings:
    $key_6c62 = { 38 0a [2] 4c 12 [2] 0b 10 [2] 4c 01 [2] 02 0d [2] 0e 07 [2] 19 0c [2] 02 42 [2] 3f }

  condition:
    any of them
}