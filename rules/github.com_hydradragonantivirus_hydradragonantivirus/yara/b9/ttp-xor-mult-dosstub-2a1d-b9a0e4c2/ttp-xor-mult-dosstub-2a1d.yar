rule TTP_XOR_MULT_DOSStub_2a1d {
  strings:
    $key_2a1d = { 7e 75 [2] 0a 6d [2] 4d 6f [2] 0a 7e [2] 44 72 [2] 48 78 [2] 5f 73 [2] 44 3d [2] 79 }

  condition:
    any of them
}