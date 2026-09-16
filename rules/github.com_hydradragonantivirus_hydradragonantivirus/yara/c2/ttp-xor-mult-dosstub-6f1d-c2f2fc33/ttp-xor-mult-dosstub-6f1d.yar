rule TTP_XOR_MULT_DOSStub_6f1d {
  strings:
    $key_6f1d = { 3b 75 [2] 4f 6d [2] 08 6f [2] 4f 7e [2] 01 72 [2] 0d 78 [2] 1a 73 [2] 01 3d [2] 3c }

  condition:
    any of them
}