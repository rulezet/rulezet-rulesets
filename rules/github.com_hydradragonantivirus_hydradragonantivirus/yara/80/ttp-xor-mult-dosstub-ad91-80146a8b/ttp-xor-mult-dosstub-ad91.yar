rule TTP_XOR_MULT_DOSStub_ad91 {
  strings:
    $key_ad91 = { f9 f9 [2] 8d e1 [2] ca e3 [2] 8d f2 [2] c3 fe [2] cf f4 [2] d8 ff [2] c3 b1 [2] fe }

  condition:
    any of them
}