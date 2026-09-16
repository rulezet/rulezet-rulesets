rule TTP_XOR_MULT_DOSStub_daf8 {
  strings:
    $key_daf8 = { 8e 90 [2] fa 88 [2] bd 8a [2] fa 9b [2] b4 97 [2] b8 9d [2] af 96 [2] b4 d8 [2] 89 }

  condition:
    any of them
}