rule TTP_XOR_MULT_DOSStub_da0e {
  strings:
    $key_da0e = { 8e 66 [2] fa 7e [2] bd 7c [2] fa 6d [2] b4 61 [2] b8 6b [2] af 60 [2] b4 2e [2] 89 }

  condition:
    any of them
}