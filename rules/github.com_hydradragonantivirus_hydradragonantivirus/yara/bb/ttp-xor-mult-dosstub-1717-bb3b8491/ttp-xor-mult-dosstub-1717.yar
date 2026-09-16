rule TTP_XOR_MULT_DOSStub_1717 {
  strings:
    $key_1717 = { 43 7f [2] 37 67 [2] 70 65 [2] 37 74 [2] 79 78 [2] 75 72 [2] 62 79 [2] 79 37 [2] 44 }

  condition:
    any of them
}