rule TTP_XOR_MULT_DOSStub_5a62 {
  strings:
    $key_5a62 = { 0e 0a [2] 7a 12 [2] 3d 10 [2] 7a 01 [2] 34 0d [2] 38 07 [2] 2f 0c [2] 34 42 [2] 09 }

  condition:
    any of them
}