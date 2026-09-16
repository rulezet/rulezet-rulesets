rule TTP_XOR_MULT_DOSStub_da7e {
  strings:
    $key_da7e = { 8e 16 [2] fa 0e [2] bd 0c [2] fa 1d [2] b4 11 [2] b8 1b [2] af 10 [2] b4 5e [2] 89 }

  condition:
    any of them
}