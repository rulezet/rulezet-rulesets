rule TTP_XOR_MULT_DOSStub_da2d {
  strings:
    $key_da2d = { 8e 45 [2] fa 5d [2] bd 5f [2] fa 4e [2] b4 42 [2] b8 48 [2] af 43 [2] b4 0d [2] 89 }

  condition:
    any of them
}