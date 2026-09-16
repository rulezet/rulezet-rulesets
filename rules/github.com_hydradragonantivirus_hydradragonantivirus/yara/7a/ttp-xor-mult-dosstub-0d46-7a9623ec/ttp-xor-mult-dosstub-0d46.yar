rule TTP_XOR_MULT_DOSStub_0d46 {
  strings:
    $key_0d46 = { 59 2e [2] 2d 36 [2] 6a 34 [2] 2d 25 [2] 63 29 [2] 6f 23 [2] 78 28 [2] 63 66 [2] 5e }

  condition:
    any of them
}