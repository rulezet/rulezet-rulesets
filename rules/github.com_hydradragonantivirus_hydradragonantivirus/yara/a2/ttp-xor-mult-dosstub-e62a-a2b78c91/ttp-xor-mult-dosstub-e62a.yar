rule TTP_XOR_MULT_DOSStub_e62a {
  strings:
    $key_e62a = { b2 42 [2] c6 5a [2] 81 58 [2] c6 49 [2] 88 45 [2] 84 4f [2] 93 44 [2] 88 0a [2] b5 }

  condition:
    any of them
}