rule TTP_XOR_MULT_DOSStub_3517 {
  strings:
    $key_3517 = { 61 7f [2] 15 67 [2] 52 65 [2] 15 74 [2] 5b 78 [2] 57 72 [2] 40 79 [2] 5b 37 [2] 66 }

  condition:
    any of them
}