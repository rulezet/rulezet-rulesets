rule TTP_XOR_MULT_DOSStub_ad0d {
  strings:
    $key_ad0d = { f9 65 [2] 8d 7d [2] ca 7f [2] 8d 6e [2] c3 62 [2] cf 68 [2] d8 63 [2] c3 2d [2] fe }

  condition:
    any of them
}