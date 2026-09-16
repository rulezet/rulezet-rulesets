rule TTP_XOR_MULT_DOSStub_815b {
  strings:
    $key_815b = { d5 33 [2] a1 2b [2] e6 29 [2] a1 38 [2] ef 34 [2] e3 3e [2] f4 35 [2] ef 7b [2] d2 }

  condition:
    any of them
}