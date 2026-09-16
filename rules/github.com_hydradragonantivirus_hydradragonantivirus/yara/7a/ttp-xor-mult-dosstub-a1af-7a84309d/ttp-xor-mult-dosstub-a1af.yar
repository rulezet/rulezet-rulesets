rule TTP_XOR_MULT_DOSStub_a1af {
  strings:
    $key_a1af = { f5 c7 [2] 81 df [2] c6 dd [2] 81 cc [2] cf c0 [2] c3 ca [2] d4 c1 [2] cf 8f [2] f2 }

  condition:
    any of them
}