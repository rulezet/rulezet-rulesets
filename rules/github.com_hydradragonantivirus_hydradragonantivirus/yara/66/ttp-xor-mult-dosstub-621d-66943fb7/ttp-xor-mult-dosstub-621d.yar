rule TTP_XOR_MULT_DOSStub_621d {
  strings:
    $key_621d = { 36 75 [2] 42 6d [2] 05 6f [2] 42 7e [2] 0c 72 [2] 00 78 [2] 17 73 [2] 0c 3d [2] 31 }

  condition:
    any of them
}