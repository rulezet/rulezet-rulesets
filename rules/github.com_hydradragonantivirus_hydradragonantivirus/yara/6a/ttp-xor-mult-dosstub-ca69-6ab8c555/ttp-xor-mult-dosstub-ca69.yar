rule TTP_XOR_MULT_DOSStub_ca69 {
  strings:
    $key_ca69 = { 9e 01 [2] ea 19 [2] ad 1b [2] ea 0a [2] a4 06 [2] a8 0c [2] bf 07 [2] a4 49 [2] 99 }

  condition:
    any of them
}