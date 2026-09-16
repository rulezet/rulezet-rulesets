rule TTP_XOR_MULT_DOSStub_da4b {
  strings:
    $key_da4b = { 8e 23 [2] fa 3b [2] bd 39 [2] fa 28 [2] b4 24 [2] b8 2e [2] af 25 [2] b4 6b [2] 89 }

  condition:
    any of them
}