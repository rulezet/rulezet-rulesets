rule TTP_XOR_MULT_DOSStub_da4a {
  strings:
    $key_da4a = { 8e 22 [2] fa 3a [2] bd 38 [2] fa 29 [2] b4 25 [2] b8 2f [2] af 24 [2] b4 6a [2] 89 }

  condition:
    any of them
}