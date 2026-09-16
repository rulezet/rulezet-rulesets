rule TTP_XOR_MULT_DOSStub_5939 {
  strings:
    $key_5939 = { 0d 51 [2] 79 49 [2] 3e 4b [2] 79 5a [2] 37 56 [2] 3b 5c [2] 2c 57 [2] 37 19 [2] 0a }

  condition:
    any of them
}