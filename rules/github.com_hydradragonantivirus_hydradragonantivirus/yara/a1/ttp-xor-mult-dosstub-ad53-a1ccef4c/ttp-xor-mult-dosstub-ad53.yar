rule TTP_XOR_MULT_DOSStub_ad53 {
  strings:
    $key_ad53 = { f9 3b [2] 8d 23 [2] ca 21 [2] 8d 30 [2] c3 3c [2] cf 36 [2] d8 3d [2] c3 73 [2] fe }

  condition:
    any of them
}