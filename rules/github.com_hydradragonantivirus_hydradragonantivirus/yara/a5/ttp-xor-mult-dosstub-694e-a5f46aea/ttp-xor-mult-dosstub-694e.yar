rule TTP_XOR_MULT_DOSStub_694e {
  strings:
    $key_694e = { 3d 26 [2] 49 3e [2] 0e 3c [2] 49 2d [2] 07 21 [2] 0b 2b [2] 1c 20 [2] 07 6e [2] 3a }

  condition:
    any of them
}