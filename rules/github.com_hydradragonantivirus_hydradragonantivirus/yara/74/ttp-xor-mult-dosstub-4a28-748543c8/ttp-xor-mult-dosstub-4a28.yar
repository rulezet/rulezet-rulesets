rule TTP_XOR_MULT_DOSStub_4a28 {
  strings:
    $key_4a28 = { 1e 40 [2] 6a 58 [2] 2d 5a [2] 6a 4b [2] 24 47 [2] 28 4d [2] 3f 46 [2] 24 08 [2] 19 }

  condition:
    any of them
}