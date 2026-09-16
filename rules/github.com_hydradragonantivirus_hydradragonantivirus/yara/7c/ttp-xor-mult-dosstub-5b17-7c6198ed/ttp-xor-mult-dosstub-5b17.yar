rule TTP_XOR_MULT_DOSStub_5b17 {
  strings:
    $key_5b17 = { 0f 7f [2] 7b 67 [2] 3c 65 [2] 7b 74 [2] 35 78 [2] 39 72 [2] 2e 79 [2] 35 37 [2] 08 }

  condition:
    any of them
}