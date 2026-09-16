rule TTP_XOR_MULT_DOSStub_0d16 {
  strings:
    $key_0d16 = { 59 7e [2] 2d 66 [2] 6a 64 [2] 2d 75 [2] 63 79 [2] 6f 73 [2] 78 78 [2] 63 36 [2] 5e }

  condition:
    any of them
}