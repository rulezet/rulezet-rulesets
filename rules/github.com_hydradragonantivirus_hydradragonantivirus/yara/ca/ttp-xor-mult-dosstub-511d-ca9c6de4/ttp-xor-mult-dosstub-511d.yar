rule TTP_XOR_MULT_DOSStub_511d {
  strings:
    $key_511d = { 05 75 [2] 71 6d [2] 36 6f [2] 71 7e [2] 3f 72 [2] 33 78 [2] 24 73 [2] 3f 3d [2] 02 }

  condition:
    any of them
}