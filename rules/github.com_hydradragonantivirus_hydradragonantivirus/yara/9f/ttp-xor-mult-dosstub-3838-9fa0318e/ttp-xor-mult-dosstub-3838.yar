rule TTP_XOR_MULT_DOSStub_3838 {
  strings:
    $key_3838 = { 6c 50 [2] 18 48 [2] 5f 4a [2] 18 5b [2] 56 57 [2] 5a 5d [2] 4d 56 [2] 56 18 [2] 6b }

  condition:
    any of them
}