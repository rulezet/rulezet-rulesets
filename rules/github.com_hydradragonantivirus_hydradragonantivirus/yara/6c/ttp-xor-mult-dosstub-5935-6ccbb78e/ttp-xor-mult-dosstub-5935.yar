rule TTP_XOR_MULT_DOSStub_5935 {
  strings:
    $key_5935 = { 0d 5d [2] 79 45 [2] 3e 47 [2] 79 56 [2] 37 5a [2] 3b 50 [2] 2c 5b [2] 37 15 [2] 0a }

  condition:
    any of them
}