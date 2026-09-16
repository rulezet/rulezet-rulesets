rule TTP_XOR_MULT_DOSStub_da62 {
  strings:
    $key_da62 = { 8e 0a [2] fa 12 [2] bd 10 [2] fa 01 [2] b4 0d [2] b8 07 [2] af 0c [2] b4 42 [2] 89 }

  condition:
    any of them
}