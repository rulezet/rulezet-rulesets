rule TTP_XOR_MULT_DOSStub_5a39 {
  strings:
    $key_5a39 = { 0e 51 [2] 7a 49 [2] 3d 4b [2] 7a 5a [2] 34 56 [2] 38 5c [2] 2f 57 [2] 34 19 [2] 09 }

  condition:
    any of them
}