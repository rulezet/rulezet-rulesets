rule TTP_XOR_MULT_DOSStub_a7eb {
  strings:
    $key_a7eb = { f3 83 [2] 87 9b [2] c0 99 [2] 87 88 [2] c9 84 [2] c5 8e [2] d2 85 [2] c9 cb [2] f4 }

  condition:
    any of them
}