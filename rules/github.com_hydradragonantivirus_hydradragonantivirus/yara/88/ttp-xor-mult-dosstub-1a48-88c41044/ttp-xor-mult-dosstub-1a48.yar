rule TTP_XOR_MULT_DOSStub_1a48 {
  strings:
    $key_1a48 = { 4e 20 [2] 3a 38 [2] 7d 3a [2] 3a 2b [2] 74 27 [2] 78 2d [2] 6f 26 [2] 74 68 [2] 49 }

  condition:
    any of them
}