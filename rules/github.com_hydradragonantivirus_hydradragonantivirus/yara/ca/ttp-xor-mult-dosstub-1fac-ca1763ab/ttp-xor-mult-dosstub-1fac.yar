rule TTP_XOR_MULT_DOSStub_1fac {
  strings:
    $key_1fac = { 4b c4 [2] 3f dc [2] 78 de [2] 3f cf [2] 71 c3 [2] 7d c9 [2] 6a c2 [2] 71 8c [2] 4c }

  condition:
    any of them
}