rule TTP_XOR_MULT_DOSStub_ad94 {
  strings:
    $key_ad94 = { f9 fc [2] 8d e4 [2] ca e6 [2] 8d f7 [2] c3 fb [2] cf f1 [2] d8 fa [2] c3 b4 [2] fe }

  condition:
    any of them
}