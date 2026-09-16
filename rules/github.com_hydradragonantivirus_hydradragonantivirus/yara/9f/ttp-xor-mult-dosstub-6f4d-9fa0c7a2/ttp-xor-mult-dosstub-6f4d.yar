rule TTP_XOR_MULT_DOSStub_6f4d {
  strings:
    $key_6f4d = { 3b 25 [2] 4f 3d [2] 08 3f [2] 4f 2e [2] 01 22 [2] 0d 28 [2] 1a 23 [2] 01 6d [2] 3c }

  condition:
    any of them
}