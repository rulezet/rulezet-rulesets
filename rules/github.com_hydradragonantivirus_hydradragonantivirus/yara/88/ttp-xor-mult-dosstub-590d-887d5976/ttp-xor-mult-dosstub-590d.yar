rule TTP_XOR_MULT_DOSStub_590d {
  strings:
    $key_590d = { 0d 65 [2] 79 7d [2] 3e 7f [2] 79 6e [2] 37 62 [2] 3b 68 [2] 2c 63 [2] 37 2d [2] 0a }

  condition:
    any of them
}