rule TTP_XOR_MULT_DOSStub_da74 {
  strings:
    $key_da74 = { 8e 1c [2] fa 04 [2] bd 06 [2] fa 17 [2] b4 1b [2] b8 11 [2] af 1a [2] b4 54 [2] 89 }

  condition:
    any of them
}