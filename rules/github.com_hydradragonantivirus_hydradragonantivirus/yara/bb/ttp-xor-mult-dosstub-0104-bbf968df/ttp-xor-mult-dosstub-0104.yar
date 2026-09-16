rule TTP_XOR_MULT_DOSStub_0104 {
  strings:
    $key_0104 = { 55 6c [2] 21 74 [2] 66 76 [2] 21 67 [2] 6f 6b [2] 63 61 [2] 74 6a [2] 6f 24 [2] 52 }

  condition:
    any of them
}