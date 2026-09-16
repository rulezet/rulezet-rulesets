rule TTP_XOR_MULT_DOSStub_2d01 {
  strings:
    $key_2d01 = { 79 69 [2] 0d 71 [2] 4a 73 [2] 0d 62 [2] 43 6e [2] 4f 64 [2] 58 6f [2] 43 21 [2] 7e }

  condition:
    any of them
}