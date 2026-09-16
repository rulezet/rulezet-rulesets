rule TTP_XOR_MULT_DOSStub_4b2d {
  strings:
    $key_4b2d = { 1f 45 [2] 6b 5d [2] 2c 5f [2] 6b 4e [2] 25 42 [2] 29 48 [2] 3e 43 [2] 25 0d [2] 18 }

  condition:
    any of them
}