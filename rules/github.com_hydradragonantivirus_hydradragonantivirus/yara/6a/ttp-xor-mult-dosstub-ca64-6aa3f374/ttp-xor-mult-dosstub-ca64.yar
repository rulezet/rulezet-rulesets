rule TTP_XOR_MULT_DOSStub_ca64 {
  strings:
    $key_ca64 = { 9e 0c [2] ea 14 [2] ad 16 [2] ea 07 [2] a4 0b [2] a8 01 [2] bf 0a [2] a4 44 [2] 99 }

  condition:
    any of them
}