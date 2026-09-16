rule TTP_XOR_MULT_DOSStub_2d17 {
  strings:
    $key_2d17 = { 79 7f [2] 0d 67 [2] 4a 65 [2] 0d 74 [2] 43 78 [2] 4f 72 [2] 58 79 [2] 43 37 [2] 7e }

  condition:
    any of them
}