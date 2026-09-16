rule TTP_XOR_MULT_DOSStub_1628 {
  strings:
    $key_1628 = { 42 40 [2] 36 58 [2] 71 5a [2] 36 4b [2] 78 47 [2] 74 4d [2] 63 46 [2] 78 08 [2] 45 }

  condition:
    any of them
}