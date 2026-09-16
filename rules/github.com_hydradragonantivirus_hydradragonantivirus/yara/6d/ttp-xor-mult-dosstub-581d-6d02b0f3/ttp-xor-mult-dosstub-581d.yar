rule TTP_XOR_MULT_DOSStub_581d {
  strings:
    $key_581d = { 0c 75 [2] 78 6d [2] 3f 6f [2] 78 7e [2] 36 72 [2] 3a 78 [2] 2d 73 [2] 36 3d [2] 0b }

  condition:
    any of them
}