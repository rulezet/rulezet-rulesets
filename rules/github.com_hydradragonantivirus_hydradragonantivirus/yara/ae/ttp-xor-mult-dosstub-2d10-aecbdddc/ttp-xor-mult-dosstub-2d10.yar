rule TTP_XOR_MULT_DOSStub_2d10 {
  strings:
    $key_2d10 = { 79 78 [2] 0d 60 [2] 4a 62 [2] 0d 73 [2] 43 7f [2] 4f 75 [2] 58 7e [2] 43 30 [2] 7e }

  condition:
    any of them
}