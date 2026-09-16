rule TTP_XOR_MULT_DOSStub_6445 {
  strings:
    $key_6445 = { 30 2d [2] 44 35 [2] 03 37 [2] 44 26 [2] 0a 2a [2] 06 20 [2] 11 2b [2] 0a 65 [2] 37 }

  condition:
    any of them
}