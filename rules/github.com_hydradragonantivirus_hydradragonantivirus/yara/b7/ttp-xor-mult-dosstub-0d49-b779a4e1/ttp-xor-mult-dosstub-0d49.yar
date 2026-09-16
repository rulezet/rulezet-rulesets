rule TTP_XOR_MULT_DOSStub_0d49 {
  strings:
    $key_0d49 = { 59 21 [2] 2d 39 [2] 6a 3b [2] 2d 2a [2] 63 26 [2] 6f 2c [2] 78 27 [2] 63 69 [2] 5e }

  condition:
    any of them
}