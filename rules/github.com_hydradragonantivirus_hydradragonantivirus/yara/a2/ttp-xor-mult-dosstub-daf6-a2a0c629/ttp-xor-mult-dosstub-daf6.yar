rule TTP_XOR_MULT_DOSStub_daf6 {
  strings:
    $key_daf6 = { 8e 9e [2] fa 86 [2] bd 84 [2] fa 95 [2] b4 99 [2] b8 93 [2] af 98 [2] b4 d6 [2] 89 }

  condition:
    any of them
}