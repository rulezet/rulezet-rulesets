rule TTP_XOR_MULT_DOSStub_7a1d {
  strings:
    $key_7a1d = { 2e 75 [2] 5a 6d [2] 1d 6f [2] 5a 7e [2] 14 72 [2] 18 78 [2] 0f 73 [2] 14 3d [2] 29 }

  condition:
    any of them
}