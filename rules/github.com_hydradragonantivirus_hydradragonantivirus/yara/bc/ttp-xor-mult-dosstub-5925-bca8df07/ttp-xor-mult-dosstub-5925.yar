rule TTP_XOR_MULT_DOSStub_5925 {
  strings:
    $key_5925 = { 0d 4d [2] 79 55 [2] 3e 57 [2] 79 46 [2] 37 4a [2] 3b 40 [2] 2c 4b [2] 37 05 [2] 0a }

  condition:
    any of them
}