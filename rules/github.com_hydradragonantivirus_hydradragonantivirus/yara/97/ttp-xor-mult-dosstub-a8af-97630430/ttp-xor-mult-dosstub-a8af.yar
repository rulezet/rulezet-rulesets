rule TTP_XOR_MULT_DOSStub_a8af {
  strings:
    $key_a8af = { fc c7 [2] 88 df [2] cf dd [2] 88 cc [2] c6 c0 [2] ca ca [2] dd c1 [2] c6 8f [2] fb }

  condition:
    any of them
}