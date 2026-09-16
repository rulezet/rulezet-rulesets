rule TTP_XOR_MULT_DOSStub_da4c {
  strings:
    $key_da4c = { 8e 24 [2] fa 3c [2] bd 3e [2] fa 2f [2] b4 23 [2] b8 29 [2] af 22 [2] b4 6c [2] 89 }

  condition:
    any of them
}