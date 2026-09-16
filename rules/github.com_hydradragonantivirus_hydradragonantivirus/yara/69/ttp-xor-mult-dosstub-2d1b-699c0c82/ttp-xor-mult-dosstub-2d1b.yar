rule TTP_XOR_MULT_DOSStub_2d1b {
  strings:
    $key_2d1b = { 79 73 [2] 0d 6b [2] 4a 69 [2] 0d 78 [2] 43 74 [2] 4f 7e [2] 58 75 [2] 43 3b [2] 7e }

  condition:
    any of them
}