rule TTP_XOR_MULT_DOSStub_da10 {
  strings:
    $key_da10 = { 8e 78 [2] fa 60 [2] bd 62 [2] fa 73 [2] b4 7f [2] b8 75 [2] af 7e [2] b4 30 [2] 89 }

  condition:
    any of them
}