rule TTP_XOR_MULT_DOSStub_594e {
  strings:
    $key_594e = { 0d 26 [2] 79 3e [2] 3e 3c [2] 79 2d [2] 37 21 [2] 3b 2b [2] 2c 20 [2] 37 6e [2] 0a }

  condition:
    any of them
}