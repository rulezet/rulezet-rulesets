rule TTP_XOR_MULT_DOSStub_83e3 {
  strings:
    $key_83e3 = { d7 8b [2] a3 93 [2] e4 91 [2] a3 80 [2] ed 8c [2] e1 86 [2] f6 8d [2] ed c3 [2] d0 }

  condition:
    any of them
}