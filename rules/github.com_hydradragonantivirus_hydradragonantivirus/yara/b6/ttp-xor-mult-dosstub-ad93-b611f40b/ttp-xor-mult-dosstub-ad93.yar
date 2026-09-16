rule TTP_XOR_MULT_DOSStub_ad93 {
  strings:
    $key_ad93 = { f9 fb [2] 8d e3 [2] ca e1 [2] 8d f0 [2] c3 fc [2] cf f6 [2] d8 fd [2] c3 b3 [2] fe }

  condition:
    any of them
}