rule TTP_XOR_MULT_DOSStub_381d {
  strings:
    $key_381d = { 6c 75 [2] 18 6d [2] 5f 6f [2] 18 7e [2] 56 72 [2] 5a 78 [2] 4d 73 [2] 56 3d [2] 6b }

  condition:
    any of them
}