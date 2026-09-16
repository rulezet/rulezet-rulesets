rule TTP_XOR_MULT_DOSStub_0148 {
  strings:
    $key_0148 = { 55 20 [2] 21 38 [2] 66 3a [2] 21 2b [2] 6f 27 [2] 63 2d [2] 74 26 [2] 6f 68 [2] 52 }

  condition:
    any of them
}