rule TTP_XOR_MULT_DOSStub_4fac {
  strings:
    $key_4fac = { 1b c4 [2] 6f dc [2] 28 de [2] 6f cf [2] 21 c3 [2] 2d c9 [2] 3a c2 [2] 21 8c [2] 1c }

  condition:
    any of them
}