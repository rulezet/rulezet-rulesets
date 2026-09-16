rule TTP_XOR_MULT_DOSStub_5909 {
  strings:
    $key_5909 = { 0d 61 [2] 79 79 [2] 3e 7b [2] 79 6a [2] 37 66 [2] 3b 6c [2] 2c 67 [2] 37 29 [2] 0a }

  condition:
    any of them
}