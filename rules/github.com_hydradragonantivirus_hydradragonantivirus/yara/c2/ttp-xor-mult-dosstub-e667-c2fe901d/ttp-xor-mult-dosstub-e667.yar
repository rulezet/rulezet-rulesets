rule TTP_XOR_MULT_DOSStub_e667 {
  strings:
    $key_e667 = { b2 0f [2] c6 17 [2] 81 15 [2] c6 04 [2] 88 08 [2] 84 02 [2] 93 09 [2] 88 47 [2] b5 }

  condition:
    any of them
}