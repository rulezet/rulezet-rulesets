rule TTP_XOR_MULT_DOSStub_e44e {
  strings:
    $key_e44e = { b0 26 [2] c4 3e [2] 83 3c [2] c4 2d [2] 8a 21 [2] 86 2b [2] 91 20 [2] 8a 6e [2] b7 }

  condition:
    any of them
}