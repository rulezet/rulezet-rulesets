rule TTP_XOR_MULT_DOSStub_da22 {
  strings:
    $key_da22 = { 8e 4a [2] fa 52 [2] bd 50 [2] fa 41 [2] b4 4d [2] b8 47 [2] af 4c [2] b4 02 [2] 89 }

  condition:
    any of them
}