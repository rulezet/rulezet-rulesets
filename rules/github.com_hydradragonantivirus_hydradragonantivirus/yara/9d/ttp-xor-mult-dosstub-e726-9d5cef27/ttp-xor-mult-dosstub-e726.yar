rule TTP_XOR_MULT_DOSStub_e726 {
  strings:
    $key_e726 = { b3 4e [2] c7 56 [2] 80 54 [2] c7 45 [2] 89 49 [2] 85 43 [2] 92 48 [2] 89 06 [2] b4 }

  condition:
    any of them
}