rule TTP_XOR_MULT_DOSStub_da51 {
  strings:
    $key_da51 = { 8e 39 [2] fa 21 [2] bd 23 [2] fa 32 [2] b4 3e [2] b8 34 [2] af 3f [2] b4 71 [2] 89 }

  condition:
    any of them
}