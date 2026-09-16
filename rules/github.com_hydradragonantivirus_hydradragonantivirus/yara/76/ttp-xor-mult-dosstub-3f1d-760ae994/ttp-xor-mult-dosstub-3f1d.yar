rule TTP_XOR_MULT_DOSStub_3f1d {
  strings:
    $key_3f1d = { 6b 75 [2] 1f 6d [2] 58 6f [2] 1f 7e [2] 51 72 [2] 5d 78 [2] 4a 73 [2] 51 3d [2] 6c }

  condition:
    any of them
}