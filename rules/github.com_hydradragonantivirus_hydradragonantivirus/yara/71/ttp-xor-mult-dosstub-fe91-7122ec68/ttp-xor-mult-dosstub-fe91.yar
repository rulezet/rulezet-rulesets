rule TTP_XOR_MULT_DOSStub_fe91 {
  strings:
    $key_fe91 = { aa f9 [2] de e1 [2] 99 e3 [2] de f2 [2] 90 fe [2] 9c f4 [2] 8b ff [2] 90 b1 [2] ad }

  condition:
    any of them
}