rule TTP_XOR_MULT_DOSStub_4b0d {
  strings:
    $key_4b0d = { 1f 65 [2] 6b 7d [2] 2c 7f [2] 6b 6e [2] 25 62 [2] 29 68 [2] 3e 63 [2] 25 2d [2] 18 }

  condition:
    any of them
}