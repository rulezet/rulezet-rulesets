rule TTP_XOR_MULT_DOSStub_0d32 {
  strings:
    $key_0d32 = { 59 5a [2] 2d 42 [2] 6a 40 [2] 2d 51 [2] 63 5d [2] 6f 57 [2] 78 5c [2] 63 12 [2] 5e }

  condition:
    any of them
}