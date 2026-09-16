rule TTP_XOR_MULT_DOSStub_5d45 {
  strings:
    $key_5d45 = { 09 2d [2] 7d 35 [2] 3a 37 [2] 7d 26 [2] 33 2a [2] 3f 20 [2] 28 2b [2] 33 65 [2] 0e }

  condition:
    any of them
}