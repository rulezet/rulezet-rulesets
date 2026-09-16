rule TTP_XOR_MULT_DOSStub_da59 {
  strings:
    $key_da59 = { 8e 31 [2] fa 29 [2] bd 2b [2] fa 3a [2] b4 36 [2] b8 3c [2] af 37 [2] b4 79 [2] 89 }

  condition:
    any of them
}