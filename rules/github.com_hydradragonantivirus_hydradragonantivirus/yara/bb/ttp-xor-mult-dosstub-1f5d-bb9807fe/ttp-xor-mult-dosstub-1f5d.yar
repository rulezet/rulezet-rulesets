rule TTP_XOR_MULT_DOSStub_1f5d {
  strings:
    $key_1f5d = { 4b 35 [2] 3f 2d [2] 78 2f [2] 3f 3e [2] 71 32 [2] 7d 38 [2] 6a 33 [2] 71 7d [2] 4c }

  condition:
    any of them
}