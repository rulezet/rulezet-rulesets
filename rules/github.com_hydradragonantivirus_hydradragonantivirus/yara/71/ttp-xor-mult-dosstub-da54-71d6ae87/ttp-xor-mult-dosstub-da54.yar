rule TTP_XOR_MULT_DOSStub_da54 {
  strings:
    $key_da54 = { 8e 3c [2] fa 24 [2] bd 26 [2] fa 37 [2] b4 3b [2] b8 31 [2] af 3a [2] b4 74 [2] 89 }

  condition:
    any of them
}