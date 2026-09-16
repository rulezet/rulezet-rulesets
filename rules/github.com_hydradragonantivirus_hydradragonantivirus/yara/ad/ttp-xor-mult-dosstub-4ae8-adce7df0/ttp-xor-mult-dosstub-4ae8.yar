rule TTP_XOR_MULT_DOSStub_4ae8 {
  strings:
    $key_4ae8 = { 1e 80 [2] 6a 98 [2] 2d 9a [2] 6a 8b [2] 24 87 [2] 28 8d [2] 3f 86 [2] 24 c8 [2] 19 }

  condition:
    any of them
}