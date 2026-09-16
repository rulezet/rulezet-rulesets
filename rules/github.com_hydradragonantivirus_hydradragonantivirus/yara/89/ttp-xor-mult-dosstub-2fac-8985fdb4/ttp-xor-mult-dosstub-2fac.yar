rule TTP_XOR_MULT_DOSStub_2fac {
  strings:
    $key_2fac = { 7b c4 [2] 0f dc [2] 48 de [2] 0f cf [2] 41 c3 [2] 4d c9 [2] 5a c2 [2] 41 8c [2] 7c }

  condition:
    any of them
}