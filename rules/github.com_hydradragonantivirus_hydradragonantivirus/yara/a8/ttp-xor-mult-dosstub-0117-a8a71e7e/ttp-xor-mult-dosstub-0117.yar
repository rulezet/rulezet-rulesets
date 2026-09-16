rule TTP_XOR_MULT_DOSStub_0117 {
  strings:
    $key_0117 = { 55 7f [2] 21 67 [2] 66 65 [2] 21 74 [2] 6f 78 [2] 63 72 [2] 74 79 [2] 6f 37 [2] 52 }

  condition:
    any of them
}