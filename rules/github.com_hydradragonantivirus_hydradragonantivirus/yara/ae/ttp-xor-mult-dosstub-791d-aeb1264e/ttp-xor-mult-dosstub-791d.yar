rule TTP_XOR_MULT_DOSStub_791d {
  strings:
    $key_791d = { 2d 75 [2] 59 6d [2] 1e 6f [2] 59 7e [2] 17 72 [2] 1b 78 [2] 0c 73 [2] 17 3d [2] 2a }

  condition:
    any of them
}