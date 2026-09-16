rule TTP_XOR_MULT_DOSStub_0c09 {
  strings:
    $key_0c09 = { 58 61 [2] 2c 79 [2] 6b 7b [2] 2c 6a [2] 62 66 [2] 6e 6c [2] 79 67 [2] 62 29 [2] 5f }

  condition:
    any of them
}