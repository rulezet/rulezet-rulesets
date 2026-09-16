rule TTP_XOR_MULT_DOSStub_583e {
  strings:
    $key_583e = { 0c 56 [2] 78 4e [2] 3f 4c [2] 78 5d [2] 36 51 [2] 3a 5b [2] 2d 50 [2] 36 1e [2] 0b }

  condition:
    any of them
}