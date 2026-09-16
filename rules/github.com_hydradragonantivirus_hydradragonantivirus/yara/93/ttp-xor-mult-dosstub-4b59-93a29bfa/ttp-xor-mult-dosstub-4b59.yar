rule TTP_XOR_MULT_DOSStub_4b59 {
  strings:
    $key_4b59 = { 1f 31 [2] 6b 29 [2] 2c 2b [2] 6b 3a [2] 25 36 [2] 29 3c [2] 3e 37 [2] 25 79 [2] 18 }

  condition:
    any of them
}