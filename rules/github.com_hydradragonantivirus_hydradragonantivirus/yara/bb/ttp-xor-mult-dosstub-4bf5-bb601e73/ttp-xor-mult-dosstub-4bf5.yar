rule TTP_XOR_MULT_DOSStub_4bf5 {
  strings:
    $key_4bf5 = { 1f 9d [2] 6b 85 [2] 2c 87 [2] 6b 96 [2] 25 9a [2] 29 90 [2] 3e 9b [2] 25 d5 [2] 18 }

  condition:
    any of them
}