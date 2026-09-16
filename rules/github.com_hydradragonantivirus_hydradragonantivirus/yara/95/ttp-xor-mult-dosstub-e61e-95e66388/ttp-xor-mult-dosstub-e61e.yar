rule TTP_XOR_MULT_DOSStub_e61e {
  strings:
    $key_e61e = { b2 76 [2] c6 6e [2] 81 6c [2] c6 7d [2] 88 71 [2] 84 7b [2] 93 70 [2] 88 3e [2] b5 }

  condition:
    any of them
}