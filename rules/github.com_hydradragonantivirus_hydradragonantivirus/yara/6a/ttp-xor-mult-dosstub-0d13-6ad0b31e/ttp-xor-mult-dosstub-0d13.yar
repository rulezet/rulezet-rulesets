rule TTP_XOR_MULT_DOSStub_0d13 {
  strings:
    $key_0d13 = { 59 7b [2] 2d 63 [2] 6a 61 [2] 2d 70 [2] 63 7c [2] 6f 76 [2] 78 7d [2] 63 33 [2] 5e }

  condition:
    any of them
}