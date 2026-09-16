rule TTP_XOR_MULT_DOSStub_ad1d {
  strings:
    $key_ad1d = { f9 75 [2] 8d 6d [2] ca 6f [2] 8d 7e [2] c3 72 [2] cf 78 [2] d8 73 [2] c3 3d [2] fe }

  condition:
    any of them
}