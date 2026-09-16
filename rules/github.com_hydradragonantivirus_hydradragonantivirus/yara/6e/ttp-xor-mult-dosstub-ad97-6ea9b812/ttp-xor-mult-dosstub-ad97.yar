rule TTP_XOR_MULT_DOSStub_ad97 {
  strings:
    $key_ad97 = { f9 ff [2] 8d e7 [2] ca e5 [2] 8d f4 [2] c3 f8 [2] cf f2 [2] d8 f9 [2] c3 b7 [2] fe }

  condition:
    any of them
}