rule TTP_XOR_MULT_DOSStub_a7af {
  strings:
    $key_a7af = { f3 c7 [2] 87 df [2] c0 dd [2] 87 cc [2] c9 c0 [2] c5 ca [2] d2 c1 [2] c9 8f [2] f4 }

  condition:
    any of them
}