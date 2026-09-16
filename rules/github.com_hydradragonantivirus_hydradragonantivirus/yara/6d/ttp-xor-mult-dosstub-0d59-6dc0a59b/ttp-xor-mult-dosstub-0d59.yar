rule TTP_XOR_MULT_DOSStub_0d59 {
  strings:
    $key_0d59 = { 59 31 [2] 2d 29 [2] 6a 2b [2] 2d 3a [2] 63 36 [2] 6f 3c [2] 78 37 [2] 63 79 [2] 5e }

  condition:
    any of them
}