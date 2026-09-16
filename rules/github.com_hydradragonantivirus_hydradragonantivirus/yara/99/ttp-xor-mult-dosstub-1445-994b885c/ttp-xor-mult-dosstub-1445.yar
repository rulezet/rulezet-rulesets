rule TTP_XOR_MULT_DOSStub_1445 {
  strings:
    $key_1445 = { 40 2d [2] 34 35 [2] 73 37 [2] 34 26 [2] 7a 2a [2] 76 20 [2] 61 2b [2] 7a 65 [2] 47 }

  condition:
    any of them
}