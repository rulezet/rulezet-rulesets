rule TTP_XOR_MULT_DOSStub_4ae5 {
  strings:
    $key_4ae5 = { 1e 8d [2] 6a 95 [2] 2d 97 [2] 6a 86 [2] 24 8a [2] 28 80 [2] 3f 8b [2] 24 c5 [2] 19 }

  condition:
    any of them
}