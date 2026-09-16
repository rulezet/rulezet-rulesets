rule TTP_XOR_MULT_DOSStub_1b2d {
  strings:
    $key_1b2d = { 4f 45 [2] 3b 5d [2] 7c 5f [2] 3b 4e [2] 75 42 [2] 79 48 [2] 6e 43 [2] 75 0d [2] 48 }

  condition:
    any of them
}