rule TTP_XOR_MULT_DOSStub_ade0 {
  strings:
    $key_ade0 = { f9 88 [2] 8d 90 [2] ca 92 [2] 8d 83 [2] c3 8f [2] cf 85 [2] d8 8e [2] c3 c0 [2] fe }

  condition:
    any of them
}