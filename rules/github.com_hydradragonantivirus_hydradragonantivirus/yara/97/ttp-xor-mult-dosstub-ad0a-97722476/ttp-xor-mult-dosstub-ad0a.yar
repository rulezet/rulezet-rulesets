rule TTP_XOR_MULT_DOSStub_ad0a {
  strings:
    $key_ad0a = { f9 62 [2] 8d 7a [2] ca 78 [2] 8d 69 [2] c3 65 [2] cf 6f [2] d8 64 [2] c3 2a [2] fe }

  condition:
    any of them
}