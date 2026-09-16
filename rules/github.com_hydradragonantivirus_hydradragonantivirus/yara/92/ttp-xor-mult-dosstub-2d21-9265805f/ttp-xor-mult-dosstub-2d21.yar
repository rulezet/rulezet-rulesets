rule TTP_XOR_MULT_DOSStub_2d21 {
  strings:
    $key_2d21 = { 79 49 [2] 0d 51 [2] 4a 53 [2] 0d 42 [2] 43 4e [2] 4f 44 [2] 58 4f [2] 43 01 [2] 7e }

  condition:
    any of them
}