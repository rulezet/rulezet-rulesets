rule TTP_XOR_MULT_DOSStub_4b48 {
  strings:
    $key_4b48 = { 1f 20 [2] 6b 38 [2] 2c 3a [2] 6b 2b [2] 25 27 [2] 29 2d [2] 3e 26 [2] 25 68 [2] 18 }

  condition:
    any of them
}