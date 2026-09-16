rule TTP_XOR_MULT_DOSStub_7a3d {
  strings:
    $key_7a3d = { 2e 55 [2] 5a 4d [2] 1d 4f [2] 5a 5e [2] 14 52 [2] 18 58 [2] 0f 53 [2] 14 1d [2] 29 }

  condition:
    any of them
}