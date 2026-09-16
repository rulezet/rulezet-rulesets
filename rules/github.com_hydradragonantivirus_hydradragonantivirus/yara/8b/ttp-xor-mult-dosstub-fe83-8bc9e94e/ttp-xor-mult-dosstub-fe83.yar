rule TTP_XOR_MULT_DOSStub_fe83 {
  strings:
    $key_fe83 = { aa eb [2] de f3 [2] 99 f1 [2] de e0 [2] 90 ec [2] 9c e6 [2] 8b ed [2] 90 a3 [2] ad }

  condition:
    any of them
}