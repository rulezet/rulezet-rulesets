rule TTP_XOR_MULT_DOSStub_0548 {
  strings:
    $key_0548 = { 51 20 [2] 25 38 [2] 62 3a [2] 25 2b [2] 6b 27 [2] 67 2d [2] 70 26 [2] 6b 68 [2] 56 }

  condition:
    any of them
}