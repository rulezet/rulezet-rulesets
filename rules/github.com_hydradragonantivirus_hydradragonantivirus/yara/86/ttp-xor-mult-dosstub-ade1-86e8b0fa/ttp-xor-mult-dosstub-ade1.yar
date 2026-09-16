rule TTP_XOR_MULT_DOSStub_ade1 {
  strings:
    $key_ade1 = { f9 89 [2] 8d 91 [2] ca 93 [2] 8d 82 [2] c3 8e [2] cf 84 [2] d8 8f [2] c3 c1 [2] fe }

  condition:
    any of them
}