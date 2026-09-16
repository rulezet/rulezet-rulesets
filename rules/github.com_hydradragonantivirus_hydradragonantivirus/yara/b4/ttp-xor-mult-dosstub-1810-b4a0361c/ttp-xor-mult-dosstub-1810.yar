rule TTP_XOR_MULT_DOSStub_1810 {
  strings:
    $key_1810 = { 4c 78 [2] 38 60 [2] 7f 62 [2] 38 73 [2] 76 7f [2] 7a 75 [2] 6d 7e [2] 76 30 [2] 4b }

  condition:
    any of them
}