rule TTP_XOR_MULT_DOSStub_ad7e {
  strings:
    $key_ad7e = { f9 16 [2] 8d 0e [2] ca 0c [2] 8d 1d [2] c3 11 [2] cf 1b [2] d8 10 [2] c3 5e [2] fe }

  condition:
    any of them
}