rule TTP_XOR_MULT_DOSStub_3447 {
  strings:
    $key_3447 = { 60 2f [2] 14 37 [2] 53 35 [2] 14 24 [2] 5a 28 [2] 56 22 [2] 41 29 [2] 5a 67 [2] 67 }

  condition:
    any of them
}