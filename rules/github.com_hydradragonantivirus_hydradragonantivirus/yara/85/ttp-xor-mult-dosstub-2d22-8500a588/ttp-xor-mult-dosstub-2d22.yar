rule TTP_XOR_MULT_DOSStub_2d22 {
  strings:
    $key_2d22 = { 79 4a [2] 0d 52 [2] 4a 50 [2] 0d 41 [2] 43 4d [2] 4f 47 [2] 58 4c [2] 43 02 [2] 7e }

  condition:
    any of them
}