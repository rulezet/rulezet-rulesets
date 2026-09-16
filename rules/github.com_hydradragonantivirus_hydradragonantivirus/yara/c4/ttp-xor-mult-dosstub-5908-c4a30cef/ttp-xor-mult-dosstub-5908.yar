rule TTP_XOR_MULT_DOSStub_5908 {
  strings:
    $key_5908 = { 0d 60 [2] 79 78 [2] 3e 7a [2] 79 6b [2] 37 67 [2] 3b 6d [2] 2c 66 [2] 37 28 [2] 0a }

  condition:
    any of them
}