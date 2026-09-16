rule TTP_XOR_MULT_DOSStub_da42 {
  strings:
    $key_da42 = { 8e 2a [2] fa 32 [2] bd 30 [2] fa 21 [2] b4 2d [2] b8 27 [2] af 2c [2] b4 62 [2] 89 }

  condition:
    any of them
}