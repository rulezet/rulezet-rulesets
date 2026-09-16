rule TTP_XOR_MULT_DOSStub_caf4 {
  strings:
    $key_caf4 = { 9e 9c [2] ea 84 [2] ad 86 [2] ea 97 [2] a4 9b [2] a8 91 [2] bf 9a [2] a4 d4 [2] 99 }

  condition:
    any of them
}