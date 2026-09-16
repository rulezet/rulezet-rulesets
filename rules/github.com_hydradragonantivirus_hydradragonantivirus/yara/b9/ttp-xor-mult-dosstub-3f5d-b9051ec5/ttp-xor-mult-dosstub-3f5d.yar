rule TTP_XOR_MULT_DOSStub_3f5d {
  strings:
    $key_3f5d = { 6b 35 [2] 1f 2d [2] 58 2f [2] 1f 3e [2] 51 32 [2] 5d 38 [2] 4a 33 [2] 51 7d [2] 6c }

  condition:
    any of them
}