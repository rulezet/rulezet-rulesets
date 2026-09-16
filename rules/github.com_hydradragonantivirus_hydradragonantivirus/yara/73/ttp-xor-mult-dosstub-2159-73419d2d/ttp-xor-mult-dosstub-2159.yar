rule TTP_XOR_MULT_DOSStub_2159 {
  strings:
    $key_2159 = { 75 31 [2] 01 29 [2] 46 2b [2] 01 3a [2] 4f 36 [2] 43 3c [2] 54 37 [2] 4f 79 [2] 72 }

  condition:
    any of them
}