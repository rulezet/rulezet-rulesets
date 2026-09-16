rule TTP_XOR_MULT_DOSStub_da3e {
  strings:
    $key_da3e = { 8e 56 [2] fa 4e [2] bd 4c [2] fa 5d [2] b4 51 [2] b8 5b [2] af 50 [2] b4 1e [2] 89 }

  condition:
    any of them
}