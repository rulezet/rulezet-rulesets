rule TTP_XOR_MULT_DOSStub_1300 {
  strings:
    $key_1300 = { 47 68 [2] 33 70 [2] 74 72 [2] 33 63 [2] 7d 6f [2] 71 65 [2] 66 6e [2] 7d 20 [2] 40 }

  condition:
    any of them
}