rule TTP_XOR_MULT_DOSStub_2a2d {
  strings:
    $key_2a2d = { 7e 45 [2] 0a 5d [2] 4d 5f [2] 0a 4e [2] 44 42 [2] 48 48 [2] 5f 43 [2] 44 0d [2] 79 }

  condition:
    any of them
}