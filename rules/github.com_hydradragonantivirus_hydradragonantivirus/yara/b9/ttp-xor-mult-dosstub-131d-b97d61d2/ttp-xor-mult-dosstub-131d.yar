rule TTP_XOR_MULT_DOSStub_131d {
  strings:
    $key_131d = { 47 75 [2] 33 6d [2] 74 6f [2] 33 7e [2] 7d 72 [2] 71 78 [2] 66 73 [2] 7d 3d [2] 40 }

  condition:
    any of them
}