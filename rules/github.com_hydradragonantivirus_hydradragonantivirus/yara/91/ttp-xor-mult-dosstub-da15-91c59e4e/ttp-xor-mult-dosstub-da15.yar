rule TTP_XOR_MULT_DOSStub_da15 {
  strings:
    $key_da15 = { 8e 7d [2] fa 65 [2] bd 67 [2] fa 76 [2] b4 7a [2] b8 70 [2] af 7b [2] b4 35 [2] 89 }

  condition:
    any of them
}