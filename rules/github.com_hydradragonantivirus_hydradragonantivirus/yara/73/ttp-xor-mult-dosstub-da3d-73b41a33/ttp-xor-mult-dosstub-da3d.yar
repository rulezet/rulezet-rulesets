rule TTP_XOR_MULT_DOSStub_da3d {
  strings:
    $key_da3d = { 8e 55 [2] fa 4d [2] bd 4f [2] fa 5e [2] b4 52 [2] b8 58 [2] af 53 [2] b4 1d [2] 89 }

  condition:
    any of them
}