rule TTP_XOR_MULT_DOSStub_dae4 {
  strings:
    $key_dae4 = { 8e 8c [2] fa 94 [2] bd 96 [2] fa 87 [2] b4 8b [2] b8 81 [2] af 8a [2] b4 c4 [2] 89 }

  condition:
    any of them
}