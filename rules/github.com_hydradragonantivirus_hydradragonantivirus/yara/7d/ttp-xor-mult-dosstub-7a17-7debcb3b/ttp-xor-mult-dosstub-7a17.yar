rule TTP_XOR_MULT_DOSStub_7a17 {
  strings:
    $key_7a17 = { 2e 7f [2] 5a 67 [2] 1d 65 [2] 5a 74 [2] 14 78 [2] 18 72 [2] 0f 79 [2] 14 37 [2] 29 }

  condition:
    any of them
}