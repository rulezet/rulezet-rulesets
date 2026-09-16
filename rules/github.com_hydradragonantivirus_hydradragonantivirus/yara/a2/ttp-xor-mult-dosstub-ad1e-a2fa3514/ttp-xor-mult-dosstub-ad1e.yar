rule TTP_XOR_MULT_DOSStub_ad1e {
  strings:
    $key_ad1e = { f9 76 [2] 8d 6e [2] ca 6c [2] 8d 7d [2] c3 71 [2] cf 7b [2] d8 70 [2] c3 3e [2] fe }

  condition:
    any of them
}