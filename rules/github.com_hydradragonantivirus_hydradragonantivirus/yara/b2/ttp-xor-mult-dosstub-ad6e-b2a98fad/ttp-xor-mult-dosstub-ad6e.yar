rule TTP_XOR_MULT_DOSStub_ad6e {
  strings:
    $key_ad6e = { f9 06 [2] 8d 1e [2] ca 1c [2] 8d 0d [2] c3 01 [2] cf 0b [2] d8 00 [2] c3 4e [2] fe }

  condition:
    any of them
}