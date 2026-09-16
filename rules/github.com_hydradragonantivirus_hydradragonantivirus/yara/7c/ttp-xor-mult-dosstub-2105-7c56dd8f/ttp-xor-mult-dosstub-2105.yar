rule TTP_XOR_MULT_DOSStub_2105 {
  strings:
    $key_2105 = { 75 6d [2] 01 75 [2] 46 77 [2] 01 66 [2] 4f 6a [2] 43 60 [2] 54 6b [2] 4f 25 [2] 72 }

  condition:
    any of them
}