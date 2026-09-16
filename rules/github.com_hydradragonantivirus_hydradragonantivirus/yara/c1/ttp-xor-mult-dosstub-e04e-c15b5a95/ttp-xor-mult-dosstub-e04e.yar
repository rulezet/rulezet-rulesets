rule TTP_XOR_MULT_DOSStub_e04e {
  strings:
    $key_e04e = { b4 26 [2] c0 3e [2] 87 3c [2] c0 2d [2] 8e 21 [2] 82 2b [2] 95 20 [2] 8e 6e [2] b3 }

  condition:
    any of them
}