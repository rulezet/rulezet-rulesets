rule TTP_XOR_MULT_DOSStub_a778 {
  strings:
    $key_a778 = { f3 10 [2] 87 08 [2] c0 0a [2] 87 1b [2] c9 17 [2] c5 1d [2] d2 16 [2] c9 58 [2] f4 }

  condition:
    any of them
}