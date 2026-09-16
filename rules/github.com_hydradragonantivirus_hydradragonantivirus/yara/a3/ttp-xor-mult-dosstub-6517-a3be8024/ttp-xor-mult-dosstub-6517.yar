rule TTP_XOR_MULT_DOSStub_6517 {
  strings:
    $key_6517 = { 31 7f [2] 45 67 [2] 02 65 [2] 45 74 [2] 0b 78 [2] 07 72 [2] 10 79 [2] 0b 37 [2] 36 }

  condition:
    any of them
}