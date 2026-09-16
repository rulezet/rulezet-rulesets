rule TTP_XOR_MULT_DOSStub_da7a {
  strings:
    $key_da7a = { 8e 12 [2] fa 0a [2] bd 08 [2] fa 19 [2] b4 15 [2] b8 1f [2] af 14 [2] b4 5a [2] 89 }

  condition:
    any of them
}