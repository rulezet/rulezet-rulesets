rule TTP_XOR_MULT_DOSStub_5632 {
  strings:
    $key_5632 = { 02 5a [2] 76 42 [2] 31 40 [2] 76 51 [2] 38 5d [2] 34 57 [2] 23 5c [2] 38 12 [2] 05 }

  condition:
    any of them
}