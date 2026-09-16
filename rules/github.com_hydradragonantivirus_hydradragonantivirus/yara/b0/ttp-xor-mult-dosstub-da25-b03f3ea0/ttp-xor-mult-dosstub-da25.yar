rule TTP_XOR_MULT_DOSStub_da25 {
  strings:
    $key_da25 = { 8e 4d [2] fa 55 [2] bd 57 [2] fa 46 [2] b4 4a [2] b8 40 [2] af 4b [2] b4 05 [2] 89 }

  condition:
    any of them
}