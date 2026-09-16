rule TTP_XOR_MULT_DOSStub_4317 {
  strings:
    $key_4317 = { 17 7f [2] 63 67 [2] 24 65 [2] 63 74 [2] 2d 78 [2] 21 72 [2] 36 79 [2] 2d 37 [2] 10 }

  condition:
    any of them
}