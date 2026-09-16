rule TTP_XOR_MULT_DOSStub_adf5 {
  strings:
    $key_adf5 = { f9 9d [2] 8d 85 [2] ca 87 [2] 8d 96 [2] c3 9a [2] cf 90 [2] d8 9b [2] c3 d5 [2] fe }

  condition:
    any of them
}