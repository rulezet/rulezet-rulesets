rule TTP_XOR_MULT_DOSStub_0d17 {
  strings:
    $key_0d17 = { 59 7f [2] 2d 67 [2] 6a 65 [2] 2d 74 [2] 63 78 [2] 6f 72 [2] 78 79 [2] 63 37 [2] 5e }

  condition:
    any of them
}