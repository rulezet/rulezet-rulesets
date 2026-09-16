rule TTP_XOR_MULT_DOSStub_7b17 {
  strings:
    $key_7b17 = { 2f 7f [2] 5b 67 [2] 1c 65 [2] 5b 74 [2] 15 78 [2] 19 72 [2] 0e 79 [2] 15 37 [2] 28 }

  condition:
    any of them
}