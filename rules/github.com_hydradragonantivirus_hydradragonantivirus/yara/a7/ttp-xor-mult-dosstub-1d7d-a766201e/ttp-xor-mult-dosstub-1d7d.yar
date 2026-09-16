rule TTP_XOR_MULT_DOSStub_1d7d {
  strings:
    $key_1d7d = { 49 15 [2] 3d 0d [2] 7a 0f [2] 3d 1e [2] 73 12 [2] 7f 18 [2] 68 13 [2] 73 5d [2] 4e }

  condition:
    any of them
}