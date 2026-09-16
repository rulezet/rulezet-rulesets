rule TTP_XOR_MULT_DOSStub_a166 {
  strings:
    $key_a166 = { f5 0e [2] 81 16 [2] c6 14 [2] 81 05 [2] cf 09 [2] c3 03 [2] d4 08 [2] cf 46 [2] f2 }

  condition:
    any of them
}