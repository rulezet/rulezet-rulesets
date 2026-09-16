rule TTP_XOR_MULT_DOSStub_e64c {
  strings:
    $key_e64c = { b2 24 [2] c6 3c [2] 81 3e [2] c6 2f [2] 88 23 [2] 84 29 [2] 93 22 [2] 88 6c [2] b5 }

  condition:
    any of them
}