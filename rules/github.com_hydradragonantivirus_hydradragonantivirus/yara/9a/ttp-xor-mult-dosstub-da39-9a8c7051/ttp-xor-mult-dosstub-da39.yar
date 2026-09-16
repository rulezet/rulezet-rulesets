rule TTP_XOR_MULT_DOSStub_da39 {
  strings:
    $key_da39 = { 8e 51 [2] fa 49 [2] bd 4b [2] fa 5a [2] b4 56 [2] b8 5c [2] af 57 [2] b4 19 [2] 89 }

  condition:
    any of them
}