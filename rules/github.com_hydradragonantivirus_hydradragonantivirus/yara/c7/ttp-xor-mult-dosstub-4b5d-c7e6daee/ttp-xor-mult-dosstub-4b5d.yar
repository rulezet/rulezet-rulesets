rule TTP_XOR_MULT_DOSStub_4b5d {
  strings:
    $key_4b5d = { 1f 35 [2] 6b 2d [2] 2c 2f [2] 6b 3e [2] 25 32 [2] 29 38 [2] 3e 33 [2] 25 7d [2] 18 }

  condition:
    any of them
}