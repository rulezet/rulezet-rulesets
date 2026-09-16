rule TTP_XOR_MULT_DOSStub_1317 {
  strings:
    $key_1317 = { 47 7f [2] 33 67 [2] 74 65 [2] 33 74 [2] 7d 78 [2] 71 72 [2] 66 79 [2] 7d 37 [2] 40 }

  condition:
    any of them
}