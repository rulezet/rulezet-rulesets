rule TTP_XOR_MULT_DOSStub_3245 {
  strings:
    $key_3245 = { 66 2d [2] 12 35 [2] 55 37 [2] 12 26 [2] 5c 2a [2] 50 20 [2] 47 2b [2] 5c 65 [2] 61 }

  condition:
    any of them
}