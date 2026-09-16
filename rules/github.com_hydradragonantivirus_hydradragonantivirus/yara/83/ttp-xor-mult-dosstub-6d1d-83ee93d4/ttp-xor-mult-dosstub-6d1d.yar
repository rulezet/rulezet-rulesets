rule TTP_XOR_MULT_DOSStub_6d1d {
  strings:
    $key_6d1d = { 39 75 [2] 4d 6d [2] 0a 6f [2] 4d 7e [2] 03 72 [2] 0f 78 [2] 18 73 [2] 03 3d [2] 3e }

  condition:
    any of them
}