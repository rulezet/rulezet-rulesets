rule TTP_XOR_MULT_DOSStub_ad74 {
  strings:
    $key_ad74 = { f9 1c [2] 8d 04 [2] ca 06 [2] 8d 17 [2] c3 1b [2] cf 11 [2] d8 1a [2] c3 54 [2] fe }

  condition:
    any of them
}