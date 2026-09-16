rule TTP_XOR_MULT_DOSStub_e67a {
  strings:
    $key_e67a = { b2 12 [2] c6 0a [2] 81 08 [2] c6 19 [2] 88 15 [2] 84 1f [2] 93 14 [2] 88 5a [2] b5 }

  condition:
    any of them
}