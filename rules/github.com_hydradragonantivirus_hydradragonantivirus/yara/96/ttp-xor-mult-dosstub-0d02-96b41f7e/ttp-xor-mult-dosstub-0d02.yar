rule TTP_XOR_MULT_DOSStub_0d02 {
  strings:
    $key_0d02 = { 59 6a [2] 2d 72 [2] 6a 70 [2] 2d 61 [2] 63 6d [2] 6f 67 [2] 78 6c [2] 63 22 [2] 5e }

  condition:
    any of them
}