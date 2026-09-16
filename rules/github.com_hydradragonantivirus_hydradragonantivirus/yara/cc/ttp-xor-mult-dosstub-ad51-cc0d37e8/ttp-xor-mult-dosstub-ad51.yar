rule TTP_XOR_MULT_DOSStub_ad51 {
  strings:
    $key_ad51 = { f9 39 [2] 8d 21 [2] ca 23 [2] 8d 32 [2] c3 3e [2] cf 34 [2] d8 3f [2] c3 71 [2] fe }

  condition:
    any of them
}