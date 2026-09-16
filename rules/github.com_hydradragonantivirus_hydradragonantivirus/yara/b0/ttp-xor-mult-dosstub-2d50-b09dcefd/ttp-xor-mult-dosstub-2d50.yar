rule TTP_XOR_MULT_DOSStub_2d50 {
  strings:
    $key_2d50 = { 79 38 [2] 0d 20 [2] 4a 22 [2] 0d 33 [2] 43 3f [2] 4f 35 [2] 58 3e [2] 43 70 [2] 7e }

  condition:
    any of them
}