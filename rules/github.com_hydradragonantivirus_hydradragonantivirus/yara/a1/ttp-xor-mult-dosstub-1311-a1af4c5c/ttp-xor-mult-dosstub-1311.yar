rule TTP_XOR_MULT_DOSStub_1311 {
  strings:
    $key_1311 = { 47 79 [2] 33 61 [2] 74 63 [2] 33 72 [2] 7d 7e [2] 71 74 [2] 66 7f [2] 7d 31 [2] 40 }

  condition:
    any of them
}