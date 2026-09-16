rule TTP_XOR_MULT_DOSStub_2c22 {
  strings:
    $key_2c22 = { 78 4a [2] 0c 52 [2] 4b 50 [2] 0c 41 [2] 42 4d [2] 4e 47 [2] 59 4c [2] 42 02 [2] 7f }

  condition:
    any of them
}