rule TTP_XOR_MULT_DOSStub_da7b {
  strings:
    $key_da7b = { 8e 13 [2] fa 0b [2] bd 09 [2] fa 18 [2] b4 14 [2] b8 1e [2] af 15 [2] b4 5b [2] 89 }

  condition:
    any of them
}