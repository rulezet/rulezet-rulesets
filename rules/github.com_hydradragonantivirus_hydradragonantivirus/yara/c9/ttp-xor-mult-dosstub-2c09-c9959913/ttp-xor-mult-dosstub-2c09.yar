rule TTP_XOR_MULT_DOSStub_2c09 {
  strings:
    $key_2c09 = { 78 61 [2] 0c 79 [2] 4b 7b [2] 0c 6a [2] 42 66 [2] 4e 6c [2] 59 67 [2] 42 29 [2] 7f }

  condition:
    any of them
}