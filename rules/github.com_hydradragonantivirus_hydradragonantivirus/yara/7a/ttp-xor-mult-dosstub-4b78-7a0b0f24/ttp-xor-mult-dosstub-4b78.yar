rule TTP_XOR_MULT_DOSStub_4b78 {
  strings:
    $key_4b78 = { 1f 10 [2] 6b 08 [2] 2c 0a [2] 6b 1b [2] 25 17 [2] 29 1d [2] 3e 16 [2] 25 58 [2] 18 }

  condition:
    any of them
}