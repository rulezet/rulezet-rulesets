rule TTP_XOR_MULT_DOSStub_5617 {
  strings:
    $key_5617 = { 02 7f [2] 76 67 [2] 31 65 [2] 76 74 [2] 38 78 [2] 34 72 [2] 23 79 [2] 38 37 [2] 05 }

  condition:
    any of them
}