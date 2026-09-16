rule TTP_XOR_MULT_DOSStub_da31 {
  strings:
    $key_da31 = { 8e 59 [2] fa 41 [2] bd 43 [2] fa 52 [2] b4 5e [2] b8 54 [2] af 5f [2] b4 11 [2] 89 }

  condition:
    any of them
}