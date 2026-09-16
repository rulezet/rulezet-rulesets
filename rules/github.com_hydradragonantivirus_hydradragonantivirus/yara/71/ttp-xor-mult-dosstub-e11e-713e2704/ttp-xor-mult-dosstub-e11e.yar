rule TTP_XOR_MULT_DOSStub_e11e {
  strings:
    $key_e11e = { b5 76 [2] c1 6e [2] 86 6c [2] c1 7d [2] 8f 71 [2] 83 7b [2] 94 70 [2] 8f 3e [2] b2 }

  condition:
    any of them
}