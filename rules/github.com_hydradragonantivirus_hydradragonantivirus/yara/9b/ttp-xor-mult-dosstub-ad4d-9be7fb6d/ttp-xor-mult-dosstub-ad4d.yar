rule TTP_XOR_MULT_DOSStub_ad4d {
  strings:
    $key_ad4d = { f9 25 [2] 8d 3d [2] ca 3f [2] 8d 2e [2] c3 22 [2] cf 28 [2] d8 23 [2] c3 6d [2] fe }

  condition:
    any of them
}