rule TTP_XOR_MULT_DOSStub_da40 {
  strings:
    $key_da40 = { 8e 28 [2] fa 30 [2] bd 32 [2] fa 23 [2] b4 2f [2] b8 25 [2] af 2e [2] b4 60 [2] 89 }

  condition:
    any of them
}