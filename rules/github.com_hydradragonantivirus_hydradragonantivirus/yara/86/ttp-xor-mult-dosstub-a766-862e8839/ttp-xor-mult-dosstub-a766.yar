rule TTP_XOR_MULT_DOSStub_a766 {
  strings:
    $key_a766 = { f3 0e [2] 87 16 [2] c0 14 [2] 87 05 [2] c9 09 [2] c5 03 [2] d2 08 [2] c9 46 [2] f4 }

  condition:
    any of them
}