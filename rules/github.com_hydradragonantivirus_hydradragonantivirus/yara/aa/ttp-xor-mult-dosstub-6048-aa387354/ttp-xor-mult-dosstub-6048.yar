rule TTP_XOR_MULT_DOSStub_6048 {
  strings:
    $key_6048 = { 34 20 [2] 40 38 [2] 07 3a [2] 40 2b [2] 0e 27 [2] 02 2d [2] 15 26 [2] 0e 68 [2] 33 }

  condition:
    any of them
}