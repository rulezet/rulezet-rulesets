rule TTP_XOR_MULT_DOSStub_1817 {
  strings:
    $key_1817 = { 4c 7f [2] 38 67 [2] 7f 65 [2] 38 74 [2] 76 78 [2] 7a 72 [2] 6d 79 [2] 76 37 [2] 4b }

  condition:
    any of them
}