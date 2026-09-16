rule TTP_XOR_MULT_DOSStub_da13 {
  strings:
    $key_da13 = { 8e 7b [2] fa 63 [2] bd 61 [2] fa 70 [2] b4 7c [2] b8 76 [2] af 7d [2] b4 33 [2] 89 }

  condition:
    any of them
}