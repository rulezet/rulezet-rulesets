rule TTP_XOR_MULT_DOSStub_0d06 {
  strings:
    $key_0d06 = { 59 6e [2] 2d 76 [2] 6a 74 [2] 2d 65 [2] 63 69 [2] 6f 63 [2] 78 68 [2] 63 26 [2] 5e }

  condition:
    any of them
}