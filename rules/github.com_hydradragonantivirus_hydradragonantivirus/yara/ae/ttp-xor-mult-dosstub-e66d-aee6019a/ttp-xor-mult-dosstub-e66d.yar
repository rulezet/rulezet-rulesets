rule TTP_XOR_MULT_DOSStub_e66d {
  strings:
    $key_e66d = { b2 05 [2] c6 1d [2] 81 1f [2] c6 0e [2] 88 02 [2] 84 08 [2] 93 03 [2] 88 4d [2] b5 }

  condition:
    any of them
}