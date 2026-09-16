rule TTP_XOR_MULT_DOSStub_2d0d {
  strings:
    $key_2d0d = { 79 65 [2] 0d 7d [2] 4a 7f [2] 0d 6e [2] 43 62 [2] 4f 68 [2] 58 63 [2] 43 2d [2] 7e }

  condition:
    any of them
}