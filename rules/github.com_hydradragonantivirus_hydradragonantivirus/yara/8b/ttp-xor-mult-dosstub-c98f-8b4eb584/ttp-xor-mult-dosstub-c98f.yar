rule TTP_XOR_MULT_DOSStub_c98f {
  strings:
    $key_c98f = { 9d e7 [2] e9 ff [2] ae fd [2] e9 ec [2] a7 e0 [2] ab ea [2] bc e1 [2] a7 af [2] 9a }

  condition:
    any of them
}