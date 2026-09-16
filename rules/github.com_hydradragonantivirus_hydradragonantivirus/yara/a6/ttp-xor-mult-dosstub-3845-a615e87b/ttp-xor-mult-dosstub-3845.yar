rule TTP_XOR_MULT_DOSStub_3845 {
  strings:
    $key_3845 = { 6c 2d [2] 18 35 [2] 5f 37 [2] 18 26 [2] 56 2a [2] 5a 20 [2] 4d 2b [2] 56 65 [2] 6b }

  condition:
    any of them
}