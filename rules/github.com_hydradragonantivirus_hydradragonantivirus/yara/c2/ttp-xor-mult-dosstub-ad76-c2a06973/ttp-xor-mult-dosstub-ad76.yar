rule TTP_XOR_MULT_DOSStub_ad76 {
  strings:
    $key_ad76 = { f9 1e [2] 8d 06 [2] ca 04 [2] 8d 15 [2] c3 19 [2] cf 13 [2] d8 18 [2] c3 56 [2] fe }

  condition:
    any of them
}