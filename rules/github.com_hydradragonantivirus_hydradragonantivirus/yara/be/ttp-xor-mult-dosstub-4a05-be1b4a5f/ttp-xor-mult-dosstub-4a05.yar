rule TTP_XOR_MULT_DOSStub_4a05 {
  strings:
    $key_4a05 = { 1e 6d [2] 6a 75 [2] 2d 77 [2] 6a 66 [2] 24 6a [2] 28 60 [2] 3f 6b [2] 24 25 [2] 19 }

  condition:
    any of them
}