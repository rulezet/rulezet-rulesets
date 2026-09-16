rule TTP_XOR_MULT_DOSStub_3306 {
  strings:
    $key_3306 = { 67 6e [2] 13 76 [2] 54 74 [2] 13 65 [2] 5d 69 [2] 51 63 [2] 46 68 [2] 5d 26 [2] 60 }

  condition:
    any of them
}