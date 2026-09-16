rule TTP_XOR_MULT_DOSStub_0d08 {
  strings:
    $key_0d08 = { 59 60 [2] 2d 78 [2] 6a 7a [2] 2d 6b [2] 63 67 [2] 6f 6d [2] 78 66 [2] 63 28 [2] 5e }

  condition:
    any of them
}