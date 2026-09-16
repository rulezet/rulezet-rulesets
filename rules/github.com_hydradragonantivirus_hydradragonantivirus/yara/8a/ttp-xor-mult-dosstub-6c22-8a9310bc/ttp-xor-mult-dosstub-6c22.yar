rule TTP_XOR_MULT_DOSStub_6c22 {
  strings:
    $key_6c22 = { 38 4a [2] 4c 52 [2] 0b 50 [2] 4c 41 [2] 02 4d [2] 0e 47 [2] 19 4c [2] 02 02 [2] 3f }

  condition:
    any of them
}