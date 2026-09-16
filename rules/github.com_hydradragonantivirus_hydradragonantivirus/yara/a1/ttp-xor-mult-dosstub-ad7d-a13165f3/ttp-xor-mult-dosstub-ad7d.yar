rule TTP_XOR_MULT_DOSStub_ad7d {
  strings:
    $key_ad7d = { f9 15 [2] 8d 0d [2] ca 0f [2] 8d 1e [2] c3 12 [2] cf 18 [2] d8 13 [2] c3 5d [2] fe }

  condition:
    any of them
}