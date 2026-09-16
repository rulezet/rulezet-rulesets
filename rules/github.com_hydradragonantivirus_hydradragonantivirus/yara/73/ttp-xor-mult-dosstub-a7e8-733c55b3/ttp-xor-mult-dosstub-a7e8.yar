rule TTP_XOR_MULT_DOSStub_a7e8 {
  strings:
    $key_a7e8 = { f3 80 [2] 87 98 [2] c0 9a [2] 87 8b [2] c9 87 [2] c5 8d [2] d2 86 [2] c9 c8 [2] f4 }

  condition:
    any of them
}