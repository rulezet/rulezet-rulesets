rule TTP_XOR_MULT_DOSStub_4a29 {
  strings:
    $key_4a29 = { 1e 41 [2] 6a 59 [2] 2d 5b [2] 6a 4a [2] 24 46 [2] 28 4c [2] 3f 47 [2] 24 09 [2] 19 }

  condition:
    any of them
}