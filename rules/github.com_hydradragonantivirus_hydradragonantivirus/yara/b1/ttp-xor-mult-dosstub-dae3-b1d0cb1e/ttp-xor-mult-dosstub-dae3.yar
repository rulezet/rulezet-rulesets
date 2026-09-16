rule TTP_XOR_MULT_DOSStub_dae3 {
  strings:
    $key_dae3 = { 8e 8b [2] fa 93 [2] bd 91 [2] fa 80 [2] b4 8c [2] b8 86 [2] af 8d [2] b4 c3 [2] 89 }

  condition:
    any of them
}