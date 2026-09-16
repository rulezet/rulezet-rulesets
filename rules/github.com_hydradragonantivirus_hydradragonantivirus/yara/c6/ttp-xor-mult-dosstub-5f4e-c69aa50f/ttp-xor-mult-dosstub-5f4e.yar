rule TTP_XOR_MULT_DOSStub_5f4e {
  strings:
    $key_5f4e = { 0b 26 [2] 7f 3e [2] 38 3c [2] 7f 2d [2] 31 21 [2] 3d 2b [2] 2a 20 [2] 31 6e [2] 0c }

  condition:
    any of them
}