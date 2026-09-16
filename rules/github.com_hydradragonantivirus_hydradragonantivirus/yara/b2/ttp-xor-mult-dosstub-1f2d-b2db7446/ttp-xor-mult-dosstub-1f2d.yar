rule TTP_XOR_MULT_DOSStub_1f2d {
  strings:
    $key_1f2d = { 4b 45 [2] 3f 5d [2] 78 5f [2] 3f 4e [2] 71 42 [2] 7d 48 [2] 6a 43 [2] 71 0d [2] 4c }

  condition:
    any of them
}