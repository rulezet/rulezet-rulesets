rule TTP_XOR_MULT_DOSStub_a1ba {
  strings:
    $key_a1ba = { f5 d2 [2] 81 ca [2] c6 c8 [2] 81 d9 [2] cf d5 [2] c3 df [2] d4 d4 [2] cf 9a [2] f2 }

  condition:
    any of them
}