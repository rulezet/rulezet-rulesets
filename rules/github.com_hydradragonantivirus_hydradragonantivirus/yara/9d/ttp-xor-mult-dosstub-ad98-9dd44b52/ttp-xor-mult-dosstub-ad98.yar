rule TTP_XOR_MULT_DOSStub_ad98 {
  strings:
    $key_ad98 = { f9 f0 [2] 8d e8 [2] ca ea [2] 8d fb [2] c3 f7 [2] cf fd [2] d8 f6 [2] c3 b8 [2] fe }

  condition:
    any of them
}