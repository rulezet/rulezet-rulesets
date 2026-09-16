rule TTP_XOR_MULT_DOSStub_5934 {
  strings:
    $key_5934 = { 0d 5c [2] 79 44 [2] 3e 46 [2] 79 57 [2] 37 5b [2] 3b 51 [2] 2c 5a [2] 37 14 [2] 0a }

  condition:
    any of them
}