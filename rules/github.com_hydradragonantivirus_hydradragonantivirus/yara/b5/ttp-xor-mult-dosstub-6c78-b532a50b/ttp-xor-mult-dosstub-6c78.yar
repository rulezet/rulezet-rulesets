rule TTP_XOR_MULT_DOSStub_6c78 {
  strings:
    $key_6c78 = { 38 10 [2] 4c 08 [2] 0b 0a [2] 4c 1b [2] 02 17 [2] 0e 1d [2] 19 16 [2] 02 58 [2] 3f }

  condition:
    any of them
}