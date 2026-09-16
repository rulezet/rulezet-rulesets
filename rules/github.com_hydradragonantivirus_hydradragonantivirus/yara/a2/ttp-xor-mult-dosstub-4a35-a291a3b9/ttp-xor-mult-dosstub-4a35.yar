rule TTP_XOR_MULT_DOSStub_4a35 {
  strings:
    $key_4a35 = { 1e 5d [2] 6a 45 [2] 2d 47 [2] 6a 56 [2] 24 5a [2] 28 50 [2] 3f 5b [2] 24 15 [2] 19 }

  condition:
    any of them
}