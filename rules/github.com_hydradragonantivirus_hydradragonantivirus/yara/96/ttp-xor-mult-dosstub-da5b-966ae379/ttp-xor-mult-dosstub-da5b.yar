rule TTP_XOR_MULT_DOSStub_da5b {
  strings:
    $key_da5b = { 8e 33 [2] fa 2b [2] bd 29 [2] fa 38 [2] b4 34 [2] b8 3e [2] af 35 [2] b4 7b [2] 89 }

  condition:
    any of them
}