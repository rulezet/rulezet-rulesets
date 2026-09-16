rule TTP_XOR_MULT_DOSStub_4bf8 {
  strings:
    $key_4bf8 = { 1f 90 [2] 6b 88 [2] 2c 8a [2] 6b 9b [2] 25 97 [2] 29 9d [2] 3e 96 [2] 25 d8 [2] 18 }

  condition:
    any of them
}