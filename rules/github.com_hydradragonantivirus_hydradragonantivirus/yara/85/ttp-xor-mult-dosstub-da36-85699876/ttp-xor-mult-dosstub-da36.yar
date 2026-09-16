rule TTP_XOR_MULT_DOSStub_da36 {
  strings:
    $key_da36 = { 8e 5e [2] fa 46 [2] bd 44 [2] fa 55 [2] b4 59 [2] b8 53 [2] af 58 [2] b4 16 [2] 89 }

  condition:
    any of them
}