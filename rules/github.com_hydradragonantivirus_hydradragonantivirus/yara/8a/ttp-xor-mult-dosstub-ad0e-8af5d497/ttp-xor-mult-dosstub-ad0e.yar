rule TTP_XOR_MULT_DOSStub_ad0e {
  strings:
    $key_ad0e = { f9 66 [2] 8d 7e [2] ca 7c [2] 8d 6d [2] c3 61 [2] cf 6b [2] d8 60 [2] c3 2e [2] fe }

  condition:
    any of them
}