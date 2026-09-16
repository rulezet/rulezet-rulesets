rule TTP_XOR_MULT_DOSStub_7f1d {
  strings:
    $key_7f1d = { 2b 75 [2] 5f 6d [2] 18 6f [2] 5f 7e [2] 11 72 [2] 1d 78 [2] 0a 73 [2] 11 3d [2] 2c }

  condition:
    any of them
}