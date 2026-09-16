rule TTP_XOR_MULT_DOSStub_4f2d {
  strings:
    $key_4f2d = { 1b 45 [2] 6f 5d [2] 28 5f [2] 6f 4e [2] 21 42 [2] 2d 48 [2] 3a 43 [2] 21 0d [2] 1c }

  condition:
    any of them
}