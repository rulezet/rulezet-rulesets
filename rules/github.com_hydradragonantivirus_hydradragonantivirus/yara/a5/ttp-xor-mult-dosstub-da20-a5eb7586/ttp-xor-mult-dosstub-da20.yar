rule TTP_XOR_MULT_DOSStub_da20 {
  strings:
    $key_da20 = { 8e 48 [2] fa 50 [2] bd 52 [2] fa 43 [2] b4 4f [2] b8 45 [2] af 4e [2] b4 00 [2] 89 }

  condition:
    any of them
}