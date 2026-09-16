rule TTP_XOR_MULT_DOSStub_ad55 {
  strings:
    $key_ad55 = { f9 3d [2] 8d 25 [2] ca 27 [2] 8d 36 [2] c3 3a [2] cf 30 [2] d8 3b [2] c3 75 [2] fe }

  condition:
    any of them
}