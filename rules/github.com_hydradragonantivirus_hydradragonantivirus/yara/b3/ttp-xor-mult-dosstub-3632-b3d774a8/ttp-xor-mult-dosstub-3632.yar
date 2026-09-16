rule TTP_XOR_MULT_DOSStub_3632 {
  strings:
    $key_3632 = { 62 5a [2] 16 42 [2] 51 40 [2] 16 51 [2] 58 5d [2] 54 57 [2] 43 5c [2] 58 12 [2] 65 }

  condition:
    any of them
}