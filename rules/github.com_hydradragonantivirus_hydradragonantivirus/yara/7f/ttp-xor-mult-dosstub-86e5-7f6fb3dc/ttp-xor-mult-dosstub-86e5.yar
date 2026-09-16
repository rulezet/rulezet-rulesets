rule TTP_XOR_MULT_DOSStub_86e5 {
  strings:
    $key_86e5 = { d2 8d [2] a6 95 [2] e1 97 [2] a6 86 [2] e8 8a [2] e4 80 [2] f3 8b [2] e8 c5 [2] d5 }

  condition:
    any of them
}