rule TTP_XOR_MULT_DOSStub_5959 {
  strings:
    $key_5959 = { 0d 31 [2] 79 29 [2] 3e 2b [2] 79 3a [2] 37 36 [2] 3b 3c [2] 2c 37 [2] 37 79 [2] 0a }

  condition:
    any of them
}