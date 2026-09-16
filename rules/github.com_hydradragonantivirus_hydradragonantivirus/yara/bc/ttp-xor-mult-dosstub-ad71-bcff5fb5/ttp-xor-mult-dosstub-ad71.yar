rule TTP_XOR_MULT_DOSStub_ad71 {
  strings:
    $key_ad71 = { f9 19 [2] 8d 01 [2] ca 03 [2] 8d 12 [2] c3 1e [2] cf 14 [2] d8 1f [2] c3 51 [2] fe }

  condition:
    any of them
}