rule TTP_XOR_MULT_DOSStub_da5c {
  strings:
    $key_da5c = { 8e 34 [2] fa 2c [2] bd 2e [2] fa 3f [2] b4 33 [2] b8 39 [2] af 32 [2] b4 7c [2] 89 }

  condition:
    any of them
}