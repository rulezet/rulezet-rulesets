rule TTP_XOR_MULT_DOSStub_da0b {
  strings:
    $key_da0b = { 8e 63 [2] fa 7b [2] bd 79 [2] fa 68 [2] b4 64 [2] b8 6e [2] af 65 [2] b4 2b [2] 89 }

  condition:
    any of them
}