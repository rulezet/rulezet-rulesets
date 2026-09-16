rule TTP_XOR_MULT_DOSStub_0102 {
  strings:
    $key_0102 = { 55 6a [2] 21 72 [2] 66 70 [2] 21 61 [2] 6f 6d [2] 63 67 [2] 74 6c [2] 6f 22 [2] 52 }

  condition:
    any of them
}