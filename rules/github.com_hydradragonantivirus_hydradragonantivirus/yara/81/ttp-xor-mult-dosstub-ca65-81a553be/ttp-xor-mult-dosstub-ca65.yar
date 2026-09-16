rule TTP_XOR_MULT_DOSStub_ca65 {
  strings:
    $key_ca65 = { 9e 0d [2] ea 15 [2] ad 17 [2] ea 06 [2] a4 0a [2] a8 00 [2] bf 0b [2] a4 45 [2] 99 }

  condition:
    any of them
}