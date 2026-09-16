rule TTP_XOR_MULT_DOSStub_4b39 {
  strings:
    $key_4b39 = { 1f 51 [2] 6b 49 [2] 2c 4b [2] 6b 5a [2] 25 56 [2] 29 5c [2] 3e 57 [2] 25 19 [2] 18 }

  condition:
    any of them
}