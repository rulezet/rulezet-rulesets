rule TTP_XOR_MULT_DOSStub_ad3e {
  strings:
    $key_ad3e = { f9 56 [2] 8d 4e [2] ca 4c [2] 8d 5d [2] c3 51 [2] cf 5b [2] d8 50 [2] c3 1e [2] fe }

  condition:
    any of them
}