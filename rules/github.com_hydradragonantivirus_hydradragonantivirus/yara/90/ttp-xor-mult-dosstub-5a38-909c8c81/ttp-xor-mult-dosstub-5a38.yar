rule TTP_XOR_MULT_DOSStub_5a38 {
  strings:
    $key_5a38 = { 0e 50 [2] 7a 48 [2] 3d 4a [2] 7a 5b [2] 34 57 [2] 38 5d [2] 2f 56 [2] 34 18 [2] 09 }

  condition:
    any of them
}