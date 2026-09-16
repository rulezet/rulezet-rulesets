rule TTP_XOR_MULT_DOSStub_0545 {
  strings:
    $key_0545 = { 51 2d [2] 25 35 [2] 62 37 [2] 25 26 [2] 6b 2a [2] 67 20 [2] 70 2b [2] 6b 65 [2] 56 }

  condition:
    any of them
}