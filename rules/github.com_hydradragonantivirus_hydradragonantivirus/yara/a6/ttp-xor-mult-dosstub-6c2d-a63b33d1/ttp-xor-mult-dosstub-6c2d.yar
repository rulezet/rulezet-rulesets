rule TTP_XOR_MULT_DOSStub_6c2d {
  strings:
    $key_6c2d = { 38 45 [2] 4c 5d [2] 0b 5f [2] 4c 4e [2] 02 42 [2] 0e 48 [2] 19 43 [2] 02 0d [2] 3f }

  condition:
    any of them
}