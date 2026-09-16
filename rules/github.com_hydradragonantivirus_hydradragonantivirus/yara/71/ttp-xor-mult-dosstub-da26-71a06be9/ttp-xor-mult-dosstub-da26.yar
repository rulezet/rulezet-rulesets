rule TTP_XOR_MULT_DOSStub_da26 {
  strings:
    $key_da26 = { 8e 4e [2] fa 56 [2] bd 54 [2] fa 45 [2] b4 49 [2] b8 43 [2] af 48 [2] b4 06 [2] 89 }

  condition:
    any of them
}