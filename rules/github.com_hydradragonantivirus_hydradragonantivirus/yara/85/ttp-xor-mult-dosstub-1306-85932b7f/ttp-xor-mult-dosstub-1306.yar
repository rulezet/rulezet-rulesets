rule TTP_XOR_MULT_DOSStub_1306 {
  strings:
    $key_1306 = { 47 6e [2] 33 76 [2] 74 74 [2] 33 65 [2] 7d 69 [2] 71 63 [2] 66 68 [2] 7d 26 [2] 40 }

  condition:
    any of them
}