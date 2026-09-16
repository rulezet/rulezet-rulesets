rule TTP_XOR_MULT_DOSStub_4b45 {
  strings:
    $key_4b45 = { 1f 2d [2] 6b 35 [2] 2c 37 [2] 6b 26 [2] 25 2a [2] 29 20 [2] 3e 2b [2] 25 65 [2] 18 }

  condition:
    any of them
}