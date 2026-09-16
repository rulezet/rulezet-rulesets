rule TTP_XOR_MULT_DOSStub_584e {
  strings:
    $key_584e = { 0c 26 [2] 78 3e [2] 3f 3c [2] 78 2d [2] 36 21 [2] 3a 2b [2] 2d 20 [2] 36 6e [2] 0b }

  condition:
    any of them
}