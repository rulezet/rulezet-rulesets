rule TTP_XOR_MULT_DOSStub_7b2d {
  strings:
    $key_7b2d = { 2f 45 [2] 5b 5d [2] 1c 5f [2] 5b 4e [2] 15 42 [2] 19 48 [2] 0e 43 [2] 15 0d [2] 28 }

  condition:
    any of them
}