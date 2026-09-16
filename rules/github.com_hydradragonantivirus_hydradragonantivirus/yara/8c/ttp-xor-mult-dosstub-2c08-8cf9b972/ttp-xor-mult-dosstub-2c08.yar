rule TTP_XOR_MULT_DOSStub_2c08 {
  strings:
    $key_2c08 = { 78 60 [2] 0c 78 [2] 4b 7a [2] 0c 6b [2] 42 67 [2] 4e 6d [2] 59 66 [2] 42 28 [2] 7f }

  condition:
    any of them
}