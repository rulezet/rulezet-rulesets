rule TTP_XOR_MULT_DOSStub_e661 {
  strings:
    $key_e661 = { b2 09 [2] c6 11 [2] 81 13 [2] c6 02 [2] 88 0e [2] 84 04 [2] 93 0f [2] 88 41 [2] b5 }

  condition:
    any of them
}