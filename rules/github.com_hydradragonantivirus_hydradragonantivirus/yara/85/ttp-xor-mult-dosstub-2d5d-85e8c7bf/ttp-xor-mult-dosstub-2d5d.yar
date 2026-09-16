rule TTP_XOR_MULT_DOSStub_2d5d {
  strings:
    $key_2d5d = { 79 35 [2] 0d 2d [2] 4a 2f [2] 0d 3e [2] 43 32 [2] 4f 38 [2] 58 33 [2] 43 7d [2] 7e }

  condition:
    any of them
}