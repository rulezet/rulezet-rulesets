rule TTP_XOR_MULT_DOSStub_ad96 {
  strings:
    $key_ad96 = { f9 fe [2] 8d e6 [2] ca e4 [2] 8d f5 [2] c3 f9 [2] cf f3 [2] d8 f8 [2] c3 b6 [2] fe }

  condition:
    any of them
}