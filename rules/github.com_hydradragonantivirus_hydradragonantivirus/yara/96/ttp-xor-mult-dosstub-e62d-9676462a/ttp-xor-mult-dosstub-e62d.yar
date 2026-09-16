rule TTP_XOR_MULT_DOSStub_e62d {
  strings:
    $key_e62d = { b2 45 [2] c6 5d [2] 81 5f [2] c6 4e [2] 88 42 [2] 84 48 [2] 93 43 [2] 88 0d [2] b5 }

  condition:
    any of them
}