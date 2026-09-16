rule TTP_XOR_MULT_DOSStub_594d {
  strings:
    $key_594d = { 0d 25 [2] 79 3d [2] 3e 3f [2] 79 2e [2] 37 22 [2] 3b 28 [2] 2c 23 [2] 37 6d [2] 0a }

  condition:
    any of them
}