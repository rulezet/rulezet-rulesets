rule TTP_XOR_MULT_DOSStub_da0a {
  strings:
    $key_da0a = { 8e 62 [2] fa 7a [2] bd 78 [2] fa 69 [2] b4 65 [2] b8 6f [2] af 64 [2] b4 2a [2] 89 }

  condition:
    any of them
}