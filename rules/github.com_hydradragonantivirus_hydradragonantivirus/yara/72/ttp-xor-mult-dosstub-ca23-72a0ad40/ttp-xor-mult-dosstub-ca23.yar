rule TTP_XOR_MULT_DOSStub_ca23 {
  strings:
    $key_ca23 = { 9e 4b [2] ea 53 [2] ad 51 [2] ea 40 [2] a4 4c [2] a8 46 [2] bf 4d [2] a4 03 [2] 99 }

  condition:
    any of them
}