rule TTP_XOR_MULT_DOSStub_0d22 {
  strings:
    $key_0d22 = { 59 4a [2] 2d 52 [2] 6a 50 [2] 2d 41 [2] 63 4d [2] 6f 47 [2] 78 4c [2] 63 02 [2] 5e }

  condition:
    any of them
}