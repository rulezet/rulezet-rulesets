rule TTP_XOR_MULT_DOSStub_e67c {
  strings:
    $key_e67c = { b2 14 [2] c6 0c [2] 81 0e [2] c6 1f [2] 88 13 [2] 84 19 [2] 93 12 [2] 88 5c [2] b5 }

  condition:
    any of them
}