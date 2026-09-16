rule TTP_XOR_MULT_DOSStub_e64e {
  strings:
    $key_e64e = { b2 26 [2] c6 3e [2] 81 3c [2] c6 2d [2] 88 21 [2] 84 2b [2] 93 20 [2] 88 6e [2] b5 }

  condition:
    any of them
}