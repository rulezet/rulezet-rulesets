rule TTP_XOR_MULT_DOSStub_da04 {
  strings:
    $key_da04 = { 8e 6c [2] fa 74 [2] bd 76 [2] fa 67 [2] b4 6b [2] b8 61 [2] af 6a [2] b4 24 [2] 89 }

  condition:
    any of them
}