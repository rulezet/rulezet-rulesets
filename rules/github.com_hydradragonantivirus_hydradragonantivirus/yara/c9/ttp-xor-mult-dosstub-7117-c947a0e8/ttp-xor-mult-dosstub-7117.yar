rule TTP_XOR_MULT_DOSStub_7117 {
  strings:
    $key_7117 = { 25 7f [2] 51 67 [2] 16 65 [2] 51 74 [2] 1f 78 [2] 13 72 [2] 04 79 [2] 1f 37 [2] 22 }

  condition:
    any of them
}