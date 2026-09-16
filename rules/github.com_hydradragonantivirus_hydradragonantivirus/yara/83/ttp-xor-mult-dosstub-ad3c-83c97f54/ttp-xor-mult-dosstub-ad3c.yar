rule TTP_XOR_MULT_DOSStub_ad3c {
  strings:
    $key_ad3c = { f9 54 [2] 8d 4c [2] ca 4e [2] 8d 5f [2] c3 53 [2] cf 59 [2] d8 52 [2] c3 1c [2] fe }

  condition:
    any of them
}