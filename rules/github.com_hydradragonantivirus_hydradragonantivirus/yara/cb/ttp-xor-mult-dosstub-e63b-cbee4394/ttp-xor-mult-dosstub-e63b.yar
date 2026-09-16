rule TTP_XOR_MULT_DOSStub_e63b {
  strings:
    $key_e63b = { b2 53 [2] c6 4b [2] 81 49 [2] c6 58 [2] 88 54 [2] 84 5e [2] 93 55 [2] 88 1b [2] b5 }

  condition:
    any of them
}