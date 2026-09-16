rule TTP_XOR_MULT_DOSStub_5045 {
  strings:
    $key_5045 = { 04 2d [2] 70 35 [2] 37 37 [2] 70 26 [2] 3e 2a [2] 32 20 [2] 25 2b [2] 3e 65 [2] 03 }

  condition:
    any of them
}