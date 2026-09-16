rule TTP_XOR_MULT_DOSStub_0d36 {
  strings:
    $key_0d36 = { 59 5e [2] 2d 46 [2] 6a 44 [2] 2d 55 [2] 63 59 [2] 6f 53 [2] 78 58 [2] 63 16 [2] 5e }

  condition:
    any of them
}