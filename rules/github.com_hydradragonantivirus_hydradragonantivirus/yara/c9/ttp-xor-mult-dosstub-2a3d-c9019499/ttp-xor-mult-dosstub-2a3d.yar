rule TTP_XOR_MULT_DOSStub_2a3d {
  strings:
    $key_2a3d = { 7e 55 [2] 0a 4d [2] 4d 4f [2] 0a 5e [2] 44 52 [2] 48 58 [2] 5f 53 [2] 44 1d [2] 79 }

  condition:
    any of them
}