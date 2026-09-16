rule TTP_XOR_MULT_DOSStub_a6af {
  strings:
    $key_a6af = { f2 c7 [2] 86 df [2] c1 dd [2] 86 cc [2] c8 c0 [2] c4 ca [2] d3 c1 [2] c8 8f [2] f5 }

  condition:
    any of them
}