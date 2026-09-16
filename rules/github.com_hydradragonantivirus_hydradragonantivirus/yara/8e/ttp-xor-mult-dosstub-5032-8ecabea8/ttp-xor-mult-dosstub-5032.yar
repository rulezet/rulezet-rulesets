rule TTP_XOR_MULT_DOSStub_5032 {
  strings:
    $key_5032 = { 04 5a [2] 70 42 [2] 37 40 [2] 70 51 [2] 3e 5d [2] 32 57 [2] 25 5c [2] 3e 12 [2] 03 }

  condition:
    any of them
}