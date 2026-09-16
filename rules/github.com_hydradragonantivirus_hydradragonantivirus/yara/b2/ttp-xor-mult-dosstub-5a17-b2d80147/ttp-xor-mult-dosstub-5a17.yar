rule TTP_XOR_MULT_DOSStub_5a17 {
  strings:
    $key_5a17 = { 0e 7f [2] 7a 67 [2] 3d 65 [2] 7a 74 [2] 34 78 [2] 38 72 [2] 2f 79 [2] 34 37 [2] 09 }

  condition:
    any of them
}