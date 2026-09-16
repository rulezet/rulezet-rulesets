rule TTP_XOR_MULT_DOSStub_5245 {
  strings:
    $key_5245 = { 06 2d [2] 72 35 [2] 35 37 [2] 72 26 [2] 3c 2a [2] 30 20 [2] 27 2b [2] 3c 65 [2] 01 }

  condition:
    any of them
}