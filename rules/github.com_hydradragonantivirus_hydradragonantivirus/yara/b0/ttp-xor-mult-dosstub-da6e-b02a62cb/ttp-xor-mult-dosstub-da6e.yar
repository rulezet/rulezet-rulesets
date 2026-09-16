rule TTP_XOR_MULT_DOSStub_da6e {
  strings:
    $key_da6e = { 8e 06 [2] fa 1e [2] bd 1c [2] fa 0d [2] b4 01 [2] b8 0b [2] af 00 [2] b4 4e [2] 89 }

  condition:
    any of them
}