rule TTP_XOR_MULT_DOSStub_284d {
  strings:
    $key_284d = { 7c 25 [2] 08 3d [2] 4f 3f [2] 08 2e [2] 46 22 [2] 4a 28 [2] 5d 23 [2] 46 6d [2] 7b }

  condition:
    any of them
}