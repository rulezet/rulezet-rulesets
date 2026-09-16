rule TTP_XOR_MULT_DOSStub_da14 {
  strings:
    $key_da14 = { 8e 7c [2] fa 64 [2] bd 66 [2] fa 77 [2] b4 7b [2] b8 71 [2] af 7a [2] b4 34 [2] 89 }

  condition:
    any of them
}