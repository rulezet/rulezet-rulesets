rule TTP_XOR_MULT_DOSStub_ad5e {
  strings:
    $key_ad5e = { f9 36 [2] 8d 2e [2] ca 2c [2] 8d 3d [2] c3 31 [2] cf 3b [2] d8 30 [2] c3 7e [2] fe }

  condition:
    any of them
}