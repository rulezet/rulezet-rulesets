rule TTP_XOR_MULT_DOSStub_ad7b {
  strings:
    $key_ad7b = { f9 13 [2] 8d 0b [2] ca 09 [2] 8d 18 [2] c3 14 [2] cf 1e [2] d8 15 [2] c3 5b [2] fe }

  condition:
    any of them
}