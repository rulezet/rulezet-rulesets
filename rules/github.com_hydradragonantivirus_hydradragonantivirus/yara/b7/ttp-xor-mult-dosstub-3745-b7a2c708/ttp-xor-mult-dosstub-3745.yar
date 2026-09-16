rule TTP_XOR_MULT_DOSStub_3745 {
  strings:
    $key_3745 = { 63 2d [2] 17 35 [2] 50 37 [2] 17 26 [2] 59 2a [2] 55 20 [2] 42 2b [2] 59 65 [2] 64 }

  condition:
    any of them
}