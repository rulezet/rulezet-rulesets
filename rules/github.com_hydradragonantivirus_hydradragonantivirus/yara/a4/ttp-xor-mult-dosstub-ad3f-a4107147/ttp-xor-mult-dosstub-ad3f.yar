rule TTP_XOR_MULT_DOSStub_ad3f {
  strings:
    $key_ad3f = { f9 57 [2] 8d 4f [2] ca 4d [2] 8d 5c [2] c3 50 [2] cf 5a [2] d8 51 [2] c3 1f [2] fe }

  condition:
    any of them
}