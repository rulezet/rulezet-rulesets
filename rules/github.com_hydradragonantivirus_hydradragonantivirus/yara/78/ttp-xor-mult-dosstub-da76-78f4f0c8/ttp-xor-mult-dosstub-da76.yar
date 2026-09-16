rule TTP_XOR_MULT_DOSStub_da76 {
  strings:
    $key_da76 = { 8e 1e [2] fa 06 [2] bd 04 [2] fa 15 [2] b4 19 [2] b8 13 [2] af 18 [2] b4 56 [2] 89 }

  condition:
    any of them
}