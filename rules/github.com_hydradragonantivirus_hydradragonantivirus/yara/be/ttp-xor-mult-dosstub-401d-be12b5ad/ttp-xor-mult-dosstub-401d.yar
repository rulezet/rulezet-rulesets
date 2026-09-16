rule TTP_XOR_MULT_DOSStub_401d {
  strings:
    $key_401d = { 14 75 [2] 60 6d [2] 27 6f [2] 60 7e [2] 2e 72 [2] 22 78 [2] 35 73 [2] 2e 3d [2] 13 }

  condition:
    any of them
}