rule TTP_XOR_MULT_DOSStub_e62b {
  strings:
    $key_e62b = { b2 43 [2] c6 5b [2] 81 59 [2] c6 48 [2] 88 44 [2] 84 4e [2] 93 45 [2] 88 0b [2] b5 }

  condition:
    any of them
}