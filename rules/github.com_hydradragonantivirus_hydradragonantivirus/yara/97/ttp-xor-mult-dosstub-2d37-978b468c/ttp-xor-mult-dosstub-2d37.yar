rule TTP_XOR_MULT_DOSStub_2d37 {
  strings:
    $key_2d37 = { 79 5f [2] 0d 47 [2] 4a 45 [2] 0d 54 [2] 43 58 [2] 4f 52 [2] 58 59 [2] 43 17 [2] 7e }

  condition:
    any of them
}