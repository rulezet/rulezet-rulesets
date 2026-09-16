rule TTP_XOR_MULT_DOSStub_281d {
  strings:
    $key_281d = { 7c 75 [2] 08 6d [2] 4f 6f [2] 08 7e [2] 46 72 [2] 4a 78 [2] 5d 73 [2] 46 3d [2] 7b }

  condition:
    any of them
}