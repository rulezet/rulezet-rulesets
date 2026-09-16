rule TTP_XOR_MULT_DOSStub_da7d {
  strings:
    $key_da7d = { 8e 15 [2] fa 0d [2] bd 0f [2] fa 1e [2] b4 12 [2] b8 18 [2] af 13 [2] b4 5d [2] 89 }

  condition:
    any of them
}