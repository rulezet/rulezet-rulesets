rule TTP_XOR_MULT_DOSStub_1d6d {
  strings:
    $key_1d6d = { 49 05 [2] 3d 1d [2] 7a 1f [2] 3d 0e [2] 73 02 [2] 7f 08 [2] 68 03 [2] 73 4d [2] 4e }

  condition:
    any of them
}