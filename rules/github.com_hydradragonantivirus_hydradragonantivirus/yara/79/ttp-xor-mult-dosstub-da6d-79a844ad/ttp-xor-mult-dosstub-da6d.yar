rule TTP_XOR_MULT_DOSStub_da6d {
  strings:
    $key_da6d = { 8e 05 [2] fa 1d [2] bd 1f [2] fa 0e [2] b4 02 [2] b8 08 [2] af 03 [2] b4 4d [2] 89 }

  condition:
    any of them
}