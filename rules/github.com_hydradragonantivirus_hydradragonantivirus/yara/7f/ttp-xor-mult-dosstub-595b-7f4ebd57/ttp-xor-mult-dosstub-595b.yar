rule TTP_XOR_MULT_DOSStub_595b {
  strings:
    $key_595b = { 0d 33 [2] 79 2b [2] 3e 29 [2] 79 38 [2] 37 34 [2] 3b 3e [2] 2c 35 [2] 37 7b [2] 0a }

  condition:
    any of them
}