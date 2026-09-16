rule TTP_XOR_MULT_DOSStub_0b2d {
  strings:
    $key_0b2d = { 5f 45 [2] 2b 5d [2] 6c 5f [2] 2b 4e [2] 65 42 [2] 69 48 [2] 7e 43 [2] 65 0d [2] 58 }

  condition:
    any of them
}