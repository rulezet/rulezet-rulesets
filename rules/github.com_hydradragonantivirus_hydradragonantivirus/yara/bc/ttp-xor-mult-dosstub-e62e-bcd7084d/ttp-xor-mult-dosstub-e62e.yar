rule TTP_XOR_MULT_DOSStub_e62e {
  strings:
    $key_e62e = { b2 46 [2] c6 5e [2] 81 5c [2] c6 4d [2] 88 41 [2] 84 4b [2] 93 40 [2] 88 0e [2] b5 }

  condition:
    any of them
}