rule TTP_XOR_MULT_DOSStub_4f5d {
  strings:
    $key_4f5d = { 1b 35 [2] 6f 2d [2] 28 2f [2] 6f 3e [2] 21 32 [2] 2d 38 [2] 3a 33 [2] 21 7d [2] 1c }

  condition:
    any of them
}