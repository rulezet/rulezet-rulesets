rule TTP_XOR_MULT_DOSStub_e34e {
  strings:
    $key_e34e = { b7 26 [2] c3 3e [2] 84 3c [2] c3 2d [2] 8d 21 [2] 81 2b [2] 96 20 [2] 8d 6e [2] b0 }

  condition:
    any of them
}