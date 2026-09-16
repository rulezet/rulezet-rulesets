rule TTP_XOR_MULT_DOSStub_6c75 {
  strings:
    $key_6c75 = { 38 1d [2] 4c 05 [2] 0b 07 [2] 4c 16 [2] 02 1a [2] 0e 10 [2] 19 1b [2] 02 55 [2] 3f }

  condition:
    any of them
}