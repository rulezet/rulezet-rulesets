rule TTP_XOR_MULT_DOSStub_2d27 {
  strings:
    $key_2d27 = { 79 4f [2] 0d 57 [2] 4a 55 [2] 0d 44 [2] 43 48 [2] 4f 42 [2] 58 49 [2] 43 07 [2] 7e }

  condition:
    any of them
}