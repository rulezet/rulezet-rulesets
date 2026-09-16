rule TTP_XOR_MULT_DOSStub_e66a {
  strings:
    $key_e66a = { b2 02 [2] c6 1a [2] 81 18 [2] c6 09 [2] 88 05 [2] 84 0f [2] 93 04 [2] 88 4a [2] b5 }

  condition:
    any of them
}