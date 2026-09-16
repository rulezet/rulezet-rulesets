rule TTP_XOR_MULT_DOSStub_3217 {
  strings:
    $key_3217 = { 66 7f [2] 12 67 [2] 55 65 [2] 12 74 [2] 5c 78 [2] 50 72 [2] 47 79 [2] 5c 37 [2] 61 }

  condition:
    any of them
}