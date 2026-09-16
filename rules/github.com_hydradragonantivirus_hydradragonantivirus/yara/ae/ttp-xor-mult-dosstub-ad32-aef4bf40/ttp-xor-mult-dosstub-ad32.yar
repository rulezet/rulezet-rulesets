rule TTP_XOR_MULT_DOSStub_ad32 {
  strings:
    $key_ad32 = { f9 5a [2] 8d 42 [2] ca 40 [2] 8d 51 [2] c3 5d [2] cf 57 [2] d8 5c [2] c3 12 [2] fe }

  condition:
    any of them
}