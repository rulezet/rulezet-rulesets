rule TTP_XOR_MULT_DOSStub_1331 {
  strings:
    $key_1331 = { 47 59 [2] 33 41 [2] 74 43 [2] 33 52 [2] 7d 5e [2] 71 54 [2] 66 5f [2] 7d 11 [2] 40 }

  condition:
    any of them
}