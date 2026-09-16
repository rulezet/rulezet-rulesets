rule TTP_XOR_MULT_DOSStub_3a05 {
  strings:
    $key_3a05 = { 6e 6d [2] 1a 75 [2] 5d 77 [2] 1a 66 [2] 54 6a [2] 58 60 [2] 4f 6b [2] 54 25 [2] 69 }

  condition:
    any of them
}