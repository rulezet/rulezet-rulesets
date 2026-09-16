rule TTP_XOR_MULT_DOSStub_2d5b {
  strings:
    $key_2d5b = { 79 33 [2] 0d 2b [2] 4a 29 [2] 0d 38 [2] 43 34 [2] 4f 3e [2] 58 35 [2] 43 7b [2] 7e }

  condition:
    any of them
}