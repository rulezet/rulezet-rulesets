rule TTP_XOR_MULT_DOSStub_2d43 {
  strings:
    $key_2d43 = { 79 2b [2] 0d 33 [2] 4a 31 [2] 0d 20 [2] 43 2c [2] 4f 26 [2] 58 2d [2] 43 63 [2] 7e }

  condition:
    any of them
}