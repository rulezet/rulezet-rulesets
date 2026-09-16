rule TTP_XOR_MULT_DOSStub_da52 {
  strings:
    $key_da52 = { 8e 3a [2] fa 22 [2] bd 20 [2] fa 31 [2] b4 3d [2] b8 37 [2] af 3c [2] b4 72 [2] 89 }

  condition:
    any of them
}