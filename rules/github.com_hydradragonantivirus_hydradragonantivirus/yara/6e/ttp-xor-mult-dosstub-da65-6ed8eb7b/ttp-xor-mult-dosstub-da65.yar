rule TTP_XOR_MULT_DOSStub_da65 {
  strings:
    $key_da65 = { 8e 0d [2] fa 15 [2] bd 17 [2] fa 06 [2] b4 0a [2] b8 00 [2] af 0b [2] b4 45 [2] 89 }

  condition:
    any of them
}