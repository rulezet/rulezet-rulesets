rule TTP_XOR_MULT_DOSStub_0d15 {
  strings:
    $key_0d15 = { 59 7d [2] 2d 65 [2] 6a 67 [2] 2d 76 [2] 63 7a [2] 6f 70 [2] 78 7b [2] 63 35 [2] 5e }

  condition:
    any of them
}