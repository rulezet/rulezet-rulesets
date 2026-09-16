rule TTP_XOR_MULT_DOSStub_5a3d {
  strings:
    $key_5a3d = { 0e 55 [2] 7a 4d [2] 3d 4f [2] 7a 5e [2] 34 52 [2] 38 58 [2] 2f 53 [2] 34 1d [2] 09 }

  condition:
    any of them
}