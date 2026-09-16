rule TTP_XOR_MULT_DOSStub_da2c {
  strings:
    $key_da2c = { 8e 44 [2] fa 5c [2] bd 5e [2] fa 4f [2] b4 43 [2] b8 49 [2] af 42 [2] b4 0c [2] 89 }

  condition:
    any of them
}