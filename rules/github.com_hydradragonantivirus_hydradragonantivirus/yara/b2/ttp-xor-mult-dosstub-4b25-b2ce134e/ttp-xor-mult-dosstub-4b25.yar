rule TTP_XOR_MULT_DOSStub_4b25 {
  strings:
    $key_4b25 = { 1f 4d [2] 6b 55 [2] 2c 57 [2] 6b 46 [2] 25 4a [2] 29 40 [2] 3e 4b [2] 25 05 [2] 18 }

  condition:
    any of them
}