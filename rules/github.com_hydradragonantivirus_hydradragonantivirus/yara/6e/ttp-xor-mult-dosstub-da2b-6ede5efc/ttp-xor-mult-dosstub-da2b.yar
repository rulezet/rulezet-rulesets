rule TTP_XOR_MULT_DOSStub_da2b {
  strings:
    $key_da2b = { 8e 43 [2] fa 5b [2] bd 59 [2] fa 48 [2] b4 44 [2] b8 4e [2] af 45 [2] b4 0b [2] 89 }

  condition:
    any of them
}