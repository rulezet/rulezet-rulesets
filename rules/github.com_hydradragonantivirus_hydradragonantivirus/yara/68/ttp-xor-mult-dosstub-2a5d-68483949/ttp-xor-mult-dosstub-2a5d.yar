rule TTP_XOR_MULT_DOSStub_2a5d {
  strings:
    $key_2a5d = { 7e 35 [2] 0a 2d [2] 4d 2f [2] 0a 3e [2] 44 32 [2] 48 38 [2] 5f 33 [2] 44 7d [2] 79 }

  condition:
    any of them
}