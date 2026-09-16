rule TTP_XOR_MULT_DOSStub_da16 {
  strings:
    $key_da16 = { 8e 7e [2] fa 66 [2] bd 64 [2] fa 75 [2] b4 79 [2] b8 73 [2] af 78 [2] b4 36 [2] 89 }

  condition:
    any of them
}