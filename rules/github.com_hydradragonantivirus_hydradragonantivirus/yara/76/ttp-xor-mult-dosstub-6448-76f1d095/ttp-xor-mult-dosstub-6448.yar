rule TTP_XOR_MULT_DOSStub_6448 {
  strings:
    $key_6448 = { 30 20 [2] 44 38 [2] 03 3a [2] 44 2b [2] 0a 27 [2] 06 2d [2] 11 26 [2] 0a 68 [2] 37 }

  condition:
    any of them
}