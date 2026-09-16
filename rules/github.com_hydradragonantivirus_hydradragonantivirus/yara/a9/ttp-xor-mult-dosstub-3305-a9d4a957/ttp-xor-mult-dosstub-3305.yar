rule TTP_XOR_MULT_DOSStub_3305 {
  strings:
    $key_3305 = { 67 6d [2] 13 75 [2] 54 77 [2] 13 66 [2] 5d 6a [2] 51 60 [2] 46 6b [2] 5d 25 [2] 60 }

  condition:
    any of them
}