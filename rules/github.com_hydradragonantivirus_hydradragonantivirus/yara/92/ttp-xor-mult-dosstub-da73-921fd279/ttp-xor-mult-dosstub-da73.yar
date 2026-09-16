rule TTP_XOR_MULT_DOSStub_da73 {
  strings:
    $key_da73 = { 8e 1b [2] fa 03 [2] bd 01 [2] fa 10 [2] b4 1c [2] b8 16 [2] af 1d [2] b4 53 [2] 89 }

  condition:
    any of them
}