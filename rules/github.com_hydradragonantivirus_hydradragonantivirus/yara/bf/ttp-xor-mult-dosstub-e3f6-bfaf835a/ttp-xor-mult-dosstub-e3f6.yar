rule TTP_XOR_MULT_DOSStub_e3f6 {
  strings:
    $key_e3f6 = { b7 9e [2] c3 86 [2] 84 84 [2] c3 95 [2] 8d 99 [2] 81 93 [2] 96 98 [2] 8d d6 [2] b0 }

  condition:
    any of them
}