rule TTP_XOR_MULT_DOSStub_2138 {
  strings:
    $key_2138 = { 75 50 [2] 01 48 [2] 46 4a [2] 01 5b [2] 4f 57 [2] 43 5d [2] 54 56 [2] 4f 18 [2] 72 }

  condition:
    any of them
}