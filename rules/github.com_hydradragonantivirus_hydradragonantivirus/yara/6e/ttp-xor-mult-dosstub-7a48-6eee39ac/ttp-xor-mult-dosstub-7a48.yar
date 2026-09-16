rule TTP_XOR_MULT_DOSStub_7a48 {
  strings:
    $key_7a48 = { 2e 20 [2] 5a 38 [2] 1d 3a [2] 5a 2b [2] 14 27 [2] 18 2d [2] 0f 26 [2] 14 68 [2] 29 }

  condition:
    any of them
}