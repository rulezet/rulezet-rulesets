rule TTP_XOR_MULT_DOSStub_521d {
  strings:
    $key_521d = { 06 75 [2] 72 6d [2] 35 6f [2] 72 7e [2] 3c 72 [2] 30 78 [2] 27 73 [2] 3c 3d [2] 01 }

  condition:
    any of them
}